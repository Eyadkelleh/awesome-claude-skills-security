---
name: api-keys
description: Scan for exposed API keys and sensitive data patterns in code repositories
---

# API Key and Sensitive Data Scanner

You are helping scan code repositories and systems for exposed API keys, credentials, and sensitive data patterns.

## Your Task

1. Understand what the user needs to scan:
   - Code repository?
   - Configuration files?
   - Log files?
   - Documentation?

2. Use pattern matching resources from `seclists-categories pattern-matching/pattern-matching/references/`:
   - API key patterns
   - AWS keys
   - Google Cloud keys
   - Private keys
   - Database connection strings
   - Passwords in code

## Common API Key Patterns

### AWS Keys
```regex
AKIA[0-9A-Z]{16}  # AWS Access Key ID
[0-9a-zA-Z/+=]{40}  # AWS Secret Access Key
```

### Google Cloud
```regex
AIza[0-9A-Za-z\\-_]{35}  # Google API Key
```

### GitHub Tokens
```regex
ghp_[0-9a-zA-Z]{36}  # GitHub Personal Access Token
gho_[0-9a-zA-Z]{36}  # GitHub OAuth Token
```

### Generic Patterns
```regex
api[_-]?key.*[=:]\s*['\"][0-9a-zA-Z]{32,}['\"]
secret.*[=:]\s*['\"][0-9a-zA-Z]{32,}['\"]
password.*[=:]\s*['\"][^'\"]+['\"]
```

## Scanning Commands

### Using grep
```bash
# Scan for API keys
grep -r -E "AKIA[0-9A-Z]{16}" .

# Scan for private keys
grep -r "BEGIN.*PRIVATE KEY" .

# Scan for passwords
grep -r -i "password\s*=\s*['\"][^'\"]*['\"]" .
```

### Using git-secrets
```bash
# Install git-secrets
git secrets --install

# Add patterns
git secrets --add 'AKIA[0-9A-Z]{16}'

# Scan repository
git secrets --scan
```

### Using truffleHog
```bash
# Scan git history
trufflehog git https://github.com/user/repo

# Scan specific paths
trufflehog filesystem /path/to/code
```

## What to Look For

1. **API Keys and Tokens**
   - Cloud provider keys (AWS, GCP, Azure)
   - Third-party service tokens
   - Payment gateway credentials

2. **Database Credentials**
   - Connection strings
   - Usernames and passwords
   - Database URLs

3. **Cryptographic Keys**
   - Private keys (RSA, SSH, TLS)
   - Certificates
   - Encryption keys

4. **Authentication Secrets**
   - JWT secrets
   - Session secrets
   - OAuth client secrets

5. **Personal Information**
   - Email addresses
   - Phone numbers
   - Social Security Numbers

## Remediation Steps

1. **Immediate Action**
   - Rotate compromised credentials immediately
   - Revoke exposed API keys
   - Update affected systems

2. **Code Cleanup**
   - Remove secrets from code
   - Use environment variables
   - Implement secret management (Vault, AWS Secrets Manager)

3. **Git History**
   - Use git-filter-branch or BFG Repo-Cleaner
   - Rewrite history to remove secrets
   - Force push cleaned history

4. **Prevention**
   - Add pre-commit hooks (git-secrets)
   - Use .gitignore for sensitive files
   - Implement secret scanning in CI/CD
   - Regular security audits

## Scanning Script Example

```python
import re
import os

patterns = {
    'AWS_KEY': r'AKIA[0-9A-Z]{16}',
    'GENERIC_API_KEY': r'api[_-]?key.*[=:]\s*[\'\"][0-9a-zA-Z]{32,}[\'\"]',
    'GENERIC_SECRET': r'secret.*[=:]\s*[\'\"][0-9a-zA-Z]{32,}[\'\"]',
    'PASSWORD': r'password\s*[=:]\s*[\'\"][^\'\"]+[\'\"]'
}

def scan_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        for name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                print(f"[{name}] Found in {filepath}: {len(matches)} matches")

for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith(('.py', '.js', '.env', '.config', '.json')):
            scan_file(os.path.join(root, file))
```

## Important Notes

⚠️ **Use Cases**:
- Scanning your own repositories
- Security audits with authorization
- Incident response
- Pre-commit validation
- CI/CD security checks

⚠️ **Best Practices**:
- Never commit secrets to version control
- Use secret management systems
- Rotate credentials regularly
- Monitor for exposed secrets
- Implement automated scanning

Help the user find and remediate exposed sensitive data responsibly.
