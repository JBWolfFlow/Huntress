# Contributing to Huntress

Thank you for your interest in contributing to Huntress! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

---

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Linux environment** (Kali Linux recommended)
- **Node.js 18+** and **npm**
- **Rust** (latest stable)
- **Python 3.10+**
- **Git** for version control
- **Docker** (for Qdrant)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Huntress.git
   cd Huntress
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/JBWolfFlow/Huntress.git
   ```

---

## Development Setup

### Initial Setup

```bash
# Install system dependencies
chmod +x setup.sh
./setup.sh

# Install Node.js dependencies
npm install

# Start Qdrant
docker-compose up -d

# Set up environment variables
cp config/.env.example .env
# Edit .env with your API keys
```

### Rust Development

```bash
cd src-tauri

# Check code
cargo check

# Run tests
cargo test

# Lint with Clippy
cargo clippy -- -D warnings

# Format code
cargo fmt
```

### TypeScript Development

```bash
# Run development server
npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format
```

---

## Development Workflow

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions/improvements

### Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Build process or auxiliary tool changes

**Example:**
```
feat(oauth): add PKCE bypass detection

Implement PKCE bypass testing with multiple attack vectors:
- Missing code_challenge detection
- Weak code_verifier analysis
- Downgrade attack testing

Closes #123
```

---

## Coding Standards

### Rust Code Standards

1. **Type Safety**: Use strong typing, avoid `unwrap()` and `expect()` in production code
2. **Error Handling**: Use `Result<T, E>` with `thiserror` or `eyre`
3. **Documentation**: Add doc comments for all public APIs
4. **Testing**: Minimum 80% code coverage
5. **Clippy**: Code must pass `cargo clippy` with no warnings
6. **Formatting**: Use `cargo fmt` before committing

**Example:**
```rust
/// Validates a target against the loaded scope.
///
/// # Arguments
/// * `target` - The target domain or IP to validate
///
/// # Returns
/// * `Ok(true)` if target is in scope
/// * `Ok(false)` if target is out of scope
/// * `Err(ScopeError)` if validation fails
///
/// # Errors
/// Returns `ScopeError::NotLoaded` if no scope is loaded.
pub fn validate_target(&self, target: &str) -> Result<bool, ScopeError> {
    let scope = self.scope.as_ref()
        .ok_or(ScopeError::NotLoaded)?;
    
    Ok(scope.is_in_scope(target))
}
```

### TypeScript Code Standards

1. **Type Safety**: Use strict TypeScript, no `any` types
2. **Error Handling**: Use `Result<T, E>` pattern or proper try-catch
3. **Documentation**: JSDoc comments for all exported functions
4. **Testing**: Minimum 80% code coverage
5. **Linting**: Code must pass ESLint with no warnings
6. **Formatting**: Use Prettier before committing

**Example:**
```typescript
/**
 * Tests an OAuth endpoint for redirect_uri manipulation vulnerabilities.
 * 
 * @param endpoint - The OAuth endpoint to test
 * @returns Array of discovered vulnerabilities
 * @throws {ValidationError} If endpoint is invalid
 */
export async function testRedirectUri(
  endpoint: OAuthEndpoint
): Promise<OAuthVulnerability[]> {
  if (!endpoint.url) {
    throw new ValidationError('Endpoint URL is required');
  }
  
  const vulnerabilities: OAuthVulnerability[] = [];
  
  for (const payload of REDIRECT_URI_PAYLOADS) {
    const result = await testPayload(endpoint, payload);
    if (result) {
      vulnerabilities.push(result);
    }
  }
  
  return vulnerabilities;
}
```

### Python Code Standards

1. **Type Hints**: Use type hints for all function signatures
2. **Documentation**: Docstrings for all public functions (Google style)
3. **Error Handling**: Use proper exception handling
4. **Testing**: Minimum 80% code coverage
5. **Linting**: Code must pass `pylint` and `mypy`
6. **Formatting**: Use `black` before committing

**Example:**
```python
def train_lora_adapter(
    training_data: List[TrainingExample],
    config: AxolotlConfig
) -> ModelVersion:
    """
    Trains a LoRA adapter on the provided training data.
    
    Args:
        training_data: List of training examples from HTB sessions
        config: Axolotl configuration for training
        
    Returns:
        ModelVersion object with training metrics
        
    Raises:
        TrainingError: If training fails
        ValidationError: If data is invalid
    """
    if not training_data:
        raise ValidationError("Training data cannot be empty")
    
    # Training logic here
    pass
```

---

## Testing Requirements

### Unit Tests

All new code must include unit tests:

**Rust:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_validation() {
        let validator = ScopeValidator::new();
        validator.load_scope("test_scope.json").unwrap();
        
        assert!(validator.validate_target("api.example.com").unwrap());
        assert!(!validator.validate_target("admin.example.com").unwrap());
    }
}
```

**TypeScript:**
```typescript
describe('OAuthHunter', () => {
  it('should detect redirect_uri manipulation', async () => {
    const hunter = new OAuthHunter(config);
    const endpoint = createTestEndpoint();
    
    const vulns = await hunter.testRedirectUri(endpoint);
    
    expect(vulns).toHaveLength(1);
    expect(vulns[0].type).toBe('redirect_uri_manipulation');
  });
});
```

### Integration Tests

For features that interact with multiple components:

```typescript
describe('End-to-End OAuth Testing', () => {
  it('should complete full OAuth hunting workflow', async () => {
    // 1. Load scope
    await loadScope('test_scope.json');
    
    // 2. Discover endpoints
    const endpoints = await discoverOAuthEndpoints('example.com');
    
    // 3. Test endpoints
    const vulns = await testAllEndpoints(endpoints);
    
    // 4. Validate findings
    const validated = await validateFindings(vulns);
    
    // 5. Check for duplicates
    const unique = await filterDuplicates(validated);
    
    expect(unique.length).toBeGreaterThan(0);
  });
});
```

### Test Coverage

- Minimum **80% code coverage** for all new code
- Run coverage reports:
  ```bash
  # Rust
  cargo tarpaulin --out Html
  
  # TypeScript
  npm run test:coverage
  ```

---

## Pull Request Process

### Before Submitting

1. **Update from upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests:**
   ```bash
   # Rust tests
   cd src-tauri && cargo test
   
   # TypeScript tests
   npm test
   
   # Python tests (if applicable)
   pytest
   ```

3. **Check code quality:**
   ```bash
   # Rust
   cargo clippy
   cargo fmt --check
   
   # TypeScript
   npm run lint
   npm run format:check
   ```

4. **Update documentation** if needed

### Submitting a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature
   ```

2. Open a pull request on GitHub

3. Fill out the PR template completely

4. Link related issues using keywords:
   - `Fixes #123`
   - `Closes #456`
   - `Relates to #789`

### PR Review Process

1. **Automated Checks**: CI must pass (tests, linting, formatting)
2. **Code Review**: At least one maintainer approval required
3. **Security Review**: Required for security-sensitive changes
4. **Documentation**: Must be updated if API changes
5. **Testing**: New features must include tests

### After Approval

- Maintainers will merge using **squash and merge**
- Your contribution will be credited in release notes

---

## Security Considerations

### Security-Sensitive Code

When working on security-critical components:

1. **Scope Validation**: Never bypass scope checks
2. **Command Execution**: Always use PTY manager, never direct shell execution
3. **Kill Switch**: Respect kill switch state in all operations
4. **Credentials**: Never log or store credentials in plain text
5. **Input Validation**: Validate all external inputs

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security concerns to the maintainers
2. Include detailed description and reproduction steps
3. Allow 90 days for fix before public disclosure

---

## Questions?

- **General Questions**: Open a GitHub Discussion
- **Bug Reports**: Open a GitHub Issue
- **Feature Requests**: Open a GitHub Issue with `enhancement` label
- **Security Issues**: Email maintainers privately

---

## License

By contributing to Huntress, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Huntress! 🎯