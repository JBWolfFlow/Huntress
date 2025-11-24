/**
 * Test: Output Capture and File Persistence Fix
 * 
 * This test verifies that the fix for the hunt failure issue works correctly:
 * 1. Tool outputs are properly captured from PTY
 * 2. Outputs are saved to files for inter-tool data passing
 * 3. Files are created and accessible for subsequent tools
 * 4. File validation provides clear error messages
 */

import { ToolExecutor, ExecutionRequest, ExecutionContext } from '../core/tools/tool_executor';
import { ToolRegistry } from '../core/tools/tool_registry';
import { getToolOutputManager } from '../utils/tool_output_manager';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Test 1: Verify PTY output capture works
 */
async function testPTYOutputCapture(): Promise<boolean> {
  console.log('\n=== Test 1: PTY Output Capture ===');
  
  try {
    const registry = new ToolRegistry();
    const executor = new ToolExecutor(registry);
    
    const context: ExecutionContext = {
      executionId: 'test_pty_capture',
      agentId: 'test_agent',
      target: 'example.com',
      timestamp: new Date(),
    };
    
    const request: ExecutionRequest = {
      command: 'echo "test output"',
      context,
      skipApproval: true, // Skip approval for testing
    };
    
    console.log('Executing test command...');
    const result = await executor.execute(request);
    
    if (!result.success) {
      console.error('❌ Command execution failed:', result.blockReason);
      return false;
    }
    
    if (!result.stdout || result.stdout.length === 0) {
      console.error('❌ No output captured');
      return false;
    }
    
    console.log('✅ Output captured:', result.stdout.substring(0, 100));
    return true;
  } catch (error) {
    console.error('❌ Test failed:', error);
    return false;
  }
}

/**
 * Test 2: Verify tool output is saved to file
 */
async function testOutputFilePersistence(): Promise<boolean> {
  console.log('\n=== Test 2: Output File Persistence ===');
  
  try {
    const outputManager = getToolOutputManager();
    
    const testOutput = 'subdomain1.example.com\nsubdomain2.example.com\nsubdomain3.example.com';
    const sessionId = 'test_session_' + Date.now();
    
    console.log('Saving test output...');
    const filePath = await outputManager.saveOutput(
      'subfinder',
      sessionId,
      testOutput
    );
    
    console.log('File saved to:', filePath);
    
    // Verify file exists
    if (!fs.existsSync(filePath)) {
      console.error('❌ File was not created');
      return false;
    }
    
    // Verify file content
    const content = fs.readFileSync(filePath, 'utf-8');
    if (content !== testOutput) {
      console.error('❌ File content does not match');
      return false;
    }
    
    console.log('✅ File created and content verified');
    
    // Cleanup
    await outputManager.cleanup([sessionId]);
    
    return true;
  } catch (error) {
    console.error('❌ Test failed:', error);
    return false;
  }
}

/**
 * Test 3: Verify file combination works
 */
async function testFileCombination(): Promise<boolean> {
  console.log('\n=== Test 3: File Combination ===');
  
  try {
    const outputManager = getToolOutputManager();
    
    // Create multiple output files
    const session1 = 'test_combine_1_' + Date.now();
    const session2 = 'test_combine_2_' + Date.now();
    
    const output1 = 'target1.example.com\ntarget2.example.com';
    const output2 = 'target3.example.com\ntarget1.example.com'; // Duplicate
    
    console.log('Creating test output files...');
    await outputManager.saveOutput('subfinder', session1, output1);
    await outputManager.saveOutput('amass', session2, output2);
    
    console.log('Combining outputs...');
    const combinedPath = await outputManager.combineOutputs(
      [session1, session2],
      'test_combined.txt'
    );
    
    console.log('Combined file:', combinedPath);
    
    // Verify combined file
    if (!fs.existsSync(combinedPath)) {
      console.error('❌ Combined file was not created');
      return false;
    }
    
    const content = fs.readFileSync(combinedPath, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    
    // Should have 3 unique targets (duplicate removed)
    if (lines.length !== 3) {
      console.error('❌ Expected 3 unique targets, got:', lines.length);
      return false;
    }
    
    console.log('✅ File combination successful, duplicates removed');
    console.log('   Unique targets:', lines.length);
    
    // Cleanup
    await outputManager.cleanup([session1, session2]);
    if (fs.existsSync(combinedPath)) {
      fs.unlinkSync(combinedPath);
    }
    
    return true;
  } catch (error) {
    console.error('❌ Test failed:', error);
    return false;
  }
}

/**
 * Test 4: Verify file validation error messages
 */
async function testFileValidation(): Promise<boolean> {
  console.log('\n=== Test 4: File Validation ===');
  
  try {
    const registry = new ToolRegistry();
    const executor = new ToolExecutor(registry);
    
    const context: ExecutionContext = {
      executionId: 'test_file_validation',
      agentId: 'test_agent',
      target: 'example.com',
      timestamp: new Date(),
    };
    
    // Test with non-existent file
    const request: ExecutionRequest = {
      command: 'httpx -l /nonexistent/file.txt -silent',
      context,
      skipApproval: true,
    };
    
    console.log('Testing with non-existent file...');
    const result = await executor.execute(request);
    
    if (result.success) {
      console.error('❌ Command should have been blocked');
      return false;
    }
    
    if (!result.blockReason?.includes('not found')) {
      console.error('❌ Expected "not found" error, got:', result.blockReason);
      return false;
    }
    
    console.log('✅ File validation correctly blocked non-existent file');
    console.log('   Error message:', result.blockReason);
    
    return true;
  } catch (error) {
    console.error('❌ Test failed:', error);
    return false;
  }
}

/**
 * Run all tests
 */
async function runAllTests(): Promise<void> {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  Output Capture and File Persistence Fix - Test Suite     ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  const tests = [
    { name: 'PTY Output Capture', fn: testPTYOutputCapture },
    { name: 'Output File Persistence', fn: testOutputFilePersistence },
    { name: 'File Combination', fn: testFileCombination },
    { name: 'File Validation', fn: testFileValidation },
  ];
  
  const results: boolean[] = [];
  
  for (const test of tests) {
    try {
      const passed = await test.fn();
      results.push(passed);
    } catch (error) {
      console.error(`\n❌ Test "${test.name}" threw exception:`, error);
      results.push(false);
    }
  }
  
  // Summary
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  Test Summary                                              ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  const passed = results.filter(r => r).length;
  const total = results.length;
  
  console.log(`\nTests Passed: ${passed}/${total}`);
  
  if (passed === total) {
    console.log('\n✅ All tests passed! The fix is working correctly.');
  } else {
    console.log('\n❌ Some tests failed. Review the output above for details.');
  }
}

// Run tests if executed directly
if (require.main === module) {
  runAllTests().catch(console.error);
}

export { runAllTests, testPTYOutputCapture, testOutputFilePersistence, testFileCombination, testFileValidation };