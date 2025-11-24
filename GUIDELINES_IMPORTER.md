# Guidelines Importer Feature

## Overview

The Guidelines Importer allows you to import HackerOne program guidelines directly into Huntress, ensuring that AI agents understand the program scope, rules, and bounty ranges before starting any testing.

## Features

### 1. **URL Import**
- Paste a HackerOne program URL
- Automatically fetches program details via HackerOne API
- Extracts scope, rules, and bounty information

### 2. **Manual Entry**
- Enter program details manually
- Useful for private programs or when API access is unavailable
- Full control over scope and rules

### 3. **Automatic Scope Loading**
- In-scope targets automatically added to scope
- Out-of-scope targets marked and excluded
- Prevents accidental testing of out-of-scope assets

### 4. **AI Agent Integration**
- Guidelines available to all AI agents via context
- Agents receive formatted prompt with program rules
- Scope validation before any testing

## Usage

### URL Import

1. Navigate to the **Scope** tab
2. Enter a HackerOne program URL:
   ```
   https://hackerone.com/security
   https://hackerone.com/programs/security
   ```
3. Click **Import**
4. Guidelines and scope are automatically loaded

### Manual Entry

1. Navigate to the **Scope** tab
2. Click **Manual Entry** button
3. Fill in the form:
   - Program Name
   - In-Scope Targets (one per line)
   - Out-of-Scope Targets (one per line)
   - Program Rules (one per line)
   - Bounty Range (min/max)
4. Click **Import Guidelines**

## Program Guidelines Display

Once imported, you'll see:

- **Program Name**: The bug bounty program name
- **Bounty Range**: Min and max bounty amounts
- **Scope Summary**: Number of in-scope and out-of-scope targets
- **Program Rules**: Key rules and restrictions
- **Import Timestamp**: When the guidelines were imported

## AI Agent Integration

### Guidelines Context

The `GuidelinesContext` provides:

```typescript
interface GuidelinesContextType {
  guidelines: ProgramGuidelines | null;
  setGuidelines: (guidelines: ProgramGuidelines | null) => void;
  getGuidelinesPrompt: () => string;
  isInScope: (target: string) => boolean;
  getBountyRange: () => { min: number; max: number } | null;
}
```

### Using Guidelines in Agents

```typescript
import { useGuidelines } from '../contexts/GuidelinesContext';

// In your agent component
const { guidelines, getGuidelinesPrompt, isInScope } = useGuidelines();

// Get formatted prompt for AI
const prompt = getGuidelinesPrompt();

// Check if target is in scope
if (isInScope('api.example.com')) {
  // Proceed with testing
}

// Get bounty range
const bountyRange = getBountyRange();
console.log(`Bounty: $${bountyRange.min} - $${bountyRange.max}`);
```

### Guidelines Prompt Format

The AI agents receive guidelines in this format:

```markdown
# Program Guidelines: Example Security Program

## Scope
### In-Scope Targets (3):
- *.example.com
- api.example.com
- app.example.com

### Out-of-Scope Targets (2):
- test.example.com (DO NOT TEST)
- staging.example.com (DO NOT TEST)

## Program Rules
1. No social engineering
2. No DoS attacks
3. Report duplicates will be closed
4. Test only during business hours

## Bounty Range
- Minimum: $100
- Maximum: $10,000

### Severity Payouts
- Critical: $5,000 - $10,000
- High: $2,000 - $5,000
- Medium: $500 - $2,000
- Low: $100 - $500

## Important Reminders
1. ONLY test in-scope targets
2. Follow all program rules strictly
3. Stop immediately if you encounter out-of-scope assets
4. Document all findings with clear proof-of-concept
5. Respect rate limits and avoid DoS conditions
```

## HackerOne API Integration

### Public Programs

For public programs, the importer uses HackerOne's public API:

```
GET https://api.hackerone.com/v1/hackers/programs/{handle}
```

No authentication required for public programs.

### Private Programs

For private programs, you'll need:

1. HackerOne API credentials
2. Add to `.env`:
   ```
   HACKERONE_API_USERNAME=your_username
   HACKERONE_API_TOKEN=your_token
   ```

3. Update the API call to include authentication:
   ```typescript
   headers: {
     'Accept': 'application/json',
     'Authorization': `Basic ${btoa(`${username}:${token}`)}`
   }
   ```

## Data Structure

### ProgramGuidelines Interface

```typescript
interface ProgramGuidelines {
  programHandle: string;
  programName: string;
  url: string;
  scope: {
    inScope: string[];
    outOfScope: string[];
  };
  rules: string[];
  bountyRange: {
    min: number;
    max: number;
  };
  responseTime?: string;
  severity: {
    critical?: string;
    high?: string;
    medium?: string;
    low?: string;
  };
  importedAt: Date;
}
```

## Scope Validation

The context provides automatic scope validation:

```typescript
// Exact match
isInScope('api.example.com') // true if in scope

// Wildcard match
// If scope includes *.example.com
isInScope('subdomain.example.com') // true
isInScope('api.subdomain.example.com') // true

// Out of scope check
isInScope('test.example.com') // false if explicitly out of scope
```

## Benefits

### 1. **Safety**
- Prevents testing out-of-scope targets
- Reduces risk of program violations
- Automatic scope validation

### 2. **Efficiency**
- Quick program setup
- Automatic scope loading
- No manual scope entry needed

### 3. **AI Awareness**
- Agents understand program rules
- Bounty-aware decision making
- Context-aware testing strategies

### 4. **Compliance**
- Follows program rules automatically
- Respects scope boundaries
- Documents program requirements

## Future Enhancements

### Planned Features

1. **Auto-Refresh**
   - Periodic guideline updates
   - Scope change notifications
   - Rule update alerts

2. **Multi-Program Support**
   - Switch between programs
   - Compare program scopes
   - Unified dashboard

3. **Enhanced API Integration**
   - Private program support
   - Invitation auto-import
   - Program statistics

4. **Smart Recommendations**
   - Suggest similar programs
   - Bounty optimization
   - Target prioritization

## Troubleshooting

### URL Import Fails

**Problem**: "Invalid HackerOne URL" error

**Solution**:
- Verify URL format: `https://hackerone.com/program-name`
- Check if program is public
- Try manual entry mode

### API Rate Limiting

**Problem**: Too many requests error

**Solution**:
- Wait a few minutes before retrying
- Use manual entry for immediate needs
- Cache guidelines locally

### Scope Not Loading

**Problem**: Scope shows 0 targets

**Solution**:
- Check if program has structured scope
- Verify API response in console
- Use manual entry to add scope

## Files

- **Component**: [`src/components/GuidelinesImporter.tsx`](src/components/GuidelinesImporter.tsx)
- **Context**: [`src/contexts/GuidelinesContext.tsx`](src/contexts/GuidelinesContext.tsx)
- **Integration**: [`src/App.tsx`](src/App.tsx)

## Related Documentation

- [PIPELINE.md](PIPELINE.md) - Development roadmap
- [SETUP.md](SETUP.md) - Setup instructions
- [OAUTH_SETUP.md](OAUTH_SETUP.md) - OAuth hunter setup

## Support

For issues or questions:
1. Check console for error messages
2. Verify HackerOne URL format
3. Try manual entry mode
4. Review API response in network tab