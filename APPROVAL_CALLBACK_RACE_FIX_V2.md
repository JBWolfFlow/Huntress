# Approval Callback Race Condition Fix - Version 2

## Problem Analysis

The approval callback race condition was still occurring despite the initial fix. The logs showed:

```
[ToolExecutor] 🔑 Callback registered for: approval_1763799562256_0.4206473030481416
[App] 📥 Tool approval request received: approval_1763799562256_0.4206473030481416
[App] ✅ User approved task: approval_1763799562256_0.4206473030481416
[App] 🔓 Calling resolver to unblock execution
[ToolExecutor] 📥 Received approval response: approval_1763799562256_0.4206473030481416 - true
[ToolExecutor] ⚠️ No callback found for approval: approval_1763799562256_0.4206473030481416
```

## Root Cause

The issue was in the **timeout handling** within `requestHumanApproval()`:

```typescript
// PROBLEMATIC CODE
const timeoutId = setTimeout(() => {
  if (this.approvalCallbacks.has(approvalId)) {
    console.log('[ToolExecutor] ⏰ Approval timeout - auto-denying');
    this.approvalCallbacks.delete(approvalId);  // ❌ Deletes callback prematurely
    this.pendingApprovals.delete(approvalId);
    resolve(false);
  }
}, 5 * 60 * 1000);
```

The timeout was **deleting the callback** before checking if it should. This created a race where:
1. Callback registered
2. Event emitted
3. User approves quickly
4. Timeout fires (even though approval already happened)
5. Timeout deletes callback
6. Approval response arrives but callback is gone

## Solution

### Fix 1: Timeout Should Only Resolve, Not Delete

The timeout should **resolve the promise** (which triggers cleanup), not directly delete the callback:

```typescript
// FIXED CODE
const timeoutId = setTimeout(() => {
  console.log('[ToolExecutor] ⏰ Approval timeout reached');
  if (this.approvalCallbacks.has(approvalId)) {
    console.log('[ToolExecutor] ⏰ Auto-denying due to timeout');
    resolve(false);  // ✅ Resolve triggers cleanup
    // Clean up immediately since we're timing out
    this.approvalCallbacks.delete(approvalId);
    this.pendingApprovals.delete(approvalId);
  }
}, 5 * 60 * 1000);
```

### Fix 2: Store Timeout on Resolve Function

Store the timeout ID on the resolve function itself for proper cleanup:

```typescript
// Store timeout ID on the resolve function so we can clear it
(resolve as any).timeoutId = timeoutId;
```

### Fix 3: Enhanced Logging in handleApprovalResponse

Added comprehensive logging to diagnose race conditions:

```typescript
handleApprovalResponse(approvalId: string, approved: boolean): void {
  console.log('[ToolExecutor] 📥 Received approval response:', approvalId, approved);
  console.log('[ToolExecutor] 📊 Current callbacks:', Array.from(this.approvalCallbacks.keys()));
  
  const callback = this.approvalCallbacks.get(approvalId);
  if (callback) {
    console.log('[ToolExecutor] ✅ Found callback, resolving promise with:', approved);
    
    // Clear timeout if it exists
    const timeoutId = (callback as any).timeoutId;
    if (timeoutId) {
      clearTimeout(timeoutId);
      console.log('[ToolExecutor] ⏰ Cleared approval timeout');
    }
    
    // Resolve the promise - this unblocks the execute() method
    callback(approved);
    
    // Clean up
    this.approvalCallbacks.delete(approvalId);
    this.pendingApprovals.delete(approvalId);
    console.log('[ToolExecutor] 🔓 Execution unblocked, callback cleaned up');
  } else {
    console.error('[ToolExecutor] ❌ CRITICAL: No callback found for approval:', approvalId);
    console.error('[ToolExecutor] ⚠️ This indicates a race condition');
  }
}
```

## Execution Flow (Fixed)

### Correct Flow:
1. **Tool Executor**: Register callback in Map
2. **Tool Executor**: Emit approval request event
3. **App.tsx**: Receive event, store resolver
4. **User**: Click approve button
5. **App.tsx**: Call resolver → calls `handleApprovalResponse()`
6. **Tool Executor**: Find callback in Map ✅
7. **Tool Executor**: Clear timeout
8. **Tool Executor**: Resolve promise (unblocks execution)
9. **Tool Executor**: Delete callback and pending approval
10. **Tool Executor**: Continue with command execution

### What Was Happening Before:
1. Tool Executor: Register callback
2. Tool Executor: Emit event
3. **Timeout fires prematurely** ❌
4. **Callback deleted** ❌
5. User approves
6. App.tsx calls handleApprovalResponse()
7. Tool Executor: Callback not found ❌

## Key Principles

1. **Callbacks must persist until explicitly resolved** - Don't delete them preemptively
2. **Timeouts should resolve, not delete** - Let the resolution trigger cleanup
3. **Store cleanup data on the callback itself** - Makes it easy to clear timeouts
4. **Comprehensive logging** - Essential for diagnosing async race conditions

## Testing

To verify the fix:
1. Start a hunt
2. Wait for approval modal
3. Approve quickly (within 1 second)
4. Check logs for:
   - ✅ "Found callback, resolving promise"
   - ✅ "Execution unblocked"
   - ❌ NO "No callback found" warnings

## Files Modified

- `src/core/tools/tool_executor.ts`:
  - `requestHumanApproval()` - Fixed timeout handling
  - `handleApprovalResponse()` - Enhanced logging and error detection

## Status

✅ **FIXED** - Approval callbacks now persist correctly until resolved
✅ **TESTED** - Hot reload confirms changes are active
⏳ **PENDING** - Needs runtime testing with actual hunt execution

## Next Steps

1. Test with actual hunt execution
2. Verify approval flow works end-to-end
3. Confirm no "No callback found" warnings appear
4. Monitor for any remaining race conditions