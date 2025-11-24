# HackerOne API Setup Guide

## Overview

To use the **URL Import** feature for program guidelines, you need to configure HackerOne API credentials. This allows Huntress to fetch program details, scope, and rules automatically.

## Why Authentication is Required

HackerOne's API requires authentication for all requests, even for public programs. This is a security measure to prevent abuse and rate limiting.

## Step-by-Step Setup

### 1. Get Your HackerOne API Token

1. Log in to HackerOne: https://hackerone.com
2. Go to Settings → API Tokens: https://hackerone.com/settings/api_token/edit
3. Click **"Create API Token"**
4. Give it a name (e.g., "Huntress")
5. Copy the generated token (you'll only see it once!)

### 2. Configure Environment Variables

#### Option A: Create .env File (Recommended)

1. Copy the example file:
   ```bash
   cd huntress/config
   cp .env.example .env
   ```

2. Edit `.env` and add your credentials:
   ```bash
   HACKERONE_API_USERNAME=your_hackerone_username
   HACKERONE_API_TOKEN=your_api_token_here
   ```

3. **Important**: Never commit `.env` to git (it's in `.gitignore`)

#### Option B: Set System Environment Variables

**Linux/Mac**:
```bash
export HACKERONE_API_USERNAME="your_username"
export HACKERONE_API_TOKEN="your_token"
```

Add to `~/.bashrc` or `~/.zshrc` to make permanent.

**Windows**:
```powershell
$env:HACKERONE_API_USERNAME="your_username"
$env:HACKERONE_API_TOKEN="your_token"
```

### 3. Restart Huntress

After setting environment variables:

```bash
# Stop the current dev server (Ctrl+C)
# Then restart:
npm run tauri dev
```

The backend will now use your credentials for API requests.

## Verification

### Test the Setup

1. Open Huntress
2. Navigate to **Scope** tab
3. Try importing a program:
   ```
   https://hackerone.com/security
   ```
4. If configured correctly, you should see:
   - Program name
   - Bounty range
   - Scope targets
   - Program rules

### Check Logs

Look for this in the terminal:
```
INFO huntress_lib::h1_api: Using authenticated HackerOne API request
INFO huntress_lib::h1_api: Successfully fetched program: Security (X in-scope, Y out-of-scope)
```

If you see:
```
WARN huntress_lib::h1_api: No HackerOne API credentials found
```

Then environment variables aren't set correctly.

## Troubleshooting

### 401 Unauthorized Error

**Problem**: "Authentication required" error

**Solutions**:
1. Verify credentials are correct
2. Check environment variables are set:
   ```bash
   echo $HACKERONE_API_USERNAME
   echo $HACKERONE_API_TOKEN
   ```
3. Restart Huntress after setting variables
4. Try regenerating your API token

### Token Not Found

**Problem**: "No HackerOne API credentials found"

**Solutions**:
1. Create `.env` file in `config/` directory
2. Or set system environment variables
3. Restart terminal/IDE after setting variables
4. Check file permissions on `.env`

### Rate Limiting

**Problem**: "Too many requests" error

**Solutions**:
1. Wait a few minutes before retrying
2. HackerOne has rate limits (typically 100 req/hour)
3. Use Manual Entry for immediate needs

## Security Best Practices

### Protect Your API Token

1. **Never commit** `.env` to version control
2. **Never share** your API token
3. **Rotate tokens** periodically
4. **Use read-only** tokens when possible

### Token Permissions

Your HackerOne API token should have:
- ✅ Read access to programs
- ✅ Read access to reports (for duplicate detection)
- ❌ No write access needed (for safety)

## Alternative: Manual Entry Mode

If you don't want to configure API credentials, you can always use **Manual Entry** mode:

1. Click **"Manual Entry"** button
2. Fill in program details manually
3. No API credentials required

This is useful for:
- Private programs
- Quick testing
- When API is unavailable
- Privacy concerns

## API Documentation

- **HackerOne API Docs**: https://api.hackerone.com/docs/v1
- **API Token Management**: https://docs.hackerone.com/programs/api-tokens.html
- **Rate Limits**: https://api.hackerone.com/docs/v1#rate-limiting

## Example .env File

```bash
# HackerOne API
HACKERONE_API_USERNAME=john_doe
HACKERONE_API_TOKEN=abc123def456ghi789jkl012mno345pqr678stu901vwx234

# Qdrant (for duplicate detection)
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=

# Anthropic (for AI agents)
ANTHROPIC_API_KEY=sk-ant-api03-...

# Burp Collaborator (optional)
COLLABORATOR_URL=https://abc123.burpcollaborator.net
```

## Next Steps

After configuring API credentials:

1. ✅ URL import will work automatically
2. ✅ Program guidelines load in seconds
3. ✅ Scope auto-imports
4. ✅ Ready for bug hunting!

## Support

If you continue to have issues:
1. Check the terminal logs for detailed error messages
2. Verify API token is valid on HackerOne
3. Try Manual Entry mode as fallback
4. Check network connectivity

---

**Remember**: Manual Entry mode always works and doesn't require any API setup!