# Awesome Claude Skills: Security Collection

## Overview

This repository contains a curated collection of security testing resources from [SecLists](https://github.com/danielmiessler/SecLists) packaged as Claude Code skills. These skills provide instant access to essential wordlists, payloads, patterns, and web shells for authorized security testing, penetration testing, CTF competitions, and security research.

The goal of this project is to provide organized, immediately accessible security testing resources that integrate seamlessly with Claude Code workflows for:

- Authorized penetration testing and security assessments
- Bug bounty program research
- CTF competition problem solving
- Security tool development and testing
- Educational security demonstrations
- Vulnerability research in controlled environments

## Available Skills

### Fuzzing
**Essential fuzzing payloads for vulnerability testing**
- SQL injection testing payloads
- Command injection patterns
- NoSQL injection vectors
- LDAP injection strings
- Special character fuzzing
- Authentication bypass patterns

### Passwords
**Curated password lists for authorized credential testing**
- 500 worst passwords
- 10K most common passwords
- 100K NCSC password list
- Dark web breach compilations
- Probable password variations

### Pattern-Matching
**Sensitive data patterns for security testing**
- API key detection patterns
- Credit card format validation
- Email address patterns
- IP address discovery
- SSN format matching
- Phone number patterns

### Payloads
**Specialized attack payloads for testing**
- XSS injection vectors
- XXE payloads
- Template injection
- File upload bypasses
- Path traversal strings

### Usernames
**Common username wordlists**
- Default usernames
- Common account names
- Service-specific usernames
- Admin account patterns

### Web-Shells
**Web shell samples for detection and analysis**
- PHP web shells
- ASP/ASPX shells
- JSP shells
- Python shells
- Perl shells

## Requirements

- **Claude Code CLI** (latest version)
- Git for cloning the repository
- Basic understanding of security testing concepts
- Authorization for security testing on target systems

## Installation

### Quick Start

Clone this repository:

```bash
git clone https://github.com/Eyadkelleh/awesome-claude-skills-security.git
cd awesome-claude-skills-security
```

### Install Individual Skills

Each category is available as a separate skill. Navigate to the skill directory you want to use:

```bash
cd seclists-categories/fuzzing
```

Or install directly via Claude Code marketplace (if available):

```bash
/plugin marketplace add Eyadkelleh/awesome-claude-skills-security
/plugin install seclists-fuzzing
```

## Usage

### Basic Pattern

```python
# Access files from any skill
import os

# Example: Load fuzzing payloads
skill_path = "references/Fuzzing"

# List all available files
for root, dirs, files in os.walk(skill_path):
    for file in files:
        if file.endswith('.txt'):
            filepath = os.path.join(root, file)
            print(f"Found: {filepath}")

            # Read file content
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read().splitlines()
                print(f"  Lines: {len(content)}")
```

### Example Use Cases

**SQL Injection Testing**
```python
# Load SQL injection payloads
with open('references/Fuzzing/quick-SQLi.txt', 'r') as f:
    sqli_payloads = f.read().splitlines()

# Test against authorized targets
for payload in sqli_payloads[:10]:
    test_injection(payload)  # Your testing function
```

**Password Policy Validation**
```python
# Load common passwords for policy testing
with open('references/Passwords/10k-most-common.txt', 'r') as f:
    common_passwords = f.read().splitlines()

# Validate password policy blocks common passwords
test_password_policy(common_passwords)
```

**API Key Detection**
```python
# Load API key patterns
with open('references/Pattern-Matching/api-keys.txt', 'r') as f:
    api_patterns = f.read().splitlines()

# Scan codebase for exposed keys
scan_for_patterns(codebase_path, api_patterns)
```

## Project Structure

```
awesome-claude-skills-security/
├── README.md                           # This file
├── seclists-categories/
│   ├── fuzzing/
│   │   ├── SKILL.md                   # Skill metadata
│   │   └── references/                # Fuzzing payloads
│   ├── passwords/
│   │   ├── SKILL.md
│   │   └── references/                # Password wordlists
│   ├── pattern-matching/
│   │   ├── SKILL.md
│   │   └── references/                # Detection patterns
│   ├── payloads/
│   │   ├── SKILL.md
│   │   └── references/                # Attack payloads
│   ├── usernames/
│   │   ├── SKILL.md
│   │   └── references/                # Username wordlists
│   └── web-shells/
│       ├── SKILL.md
│       └── references/                # Web shell samples
```

## Security & Ethics

### Authorized Use Cases

- Authorized penetration testing with written permission
- Bug bounty programs (within documented scope)
- CTF competitions and challenges
- Security research in controlled lab environments
- Testing your own systems and applications
- Educational demonstrations with proper safeguards
- Defensive security tool development

### Prohibited Use Cases

- Unauthorized access attempts against any system
- Testing systems without explicit permission
- Malicious activities or attacks
- Privacy violations or data theft
- Any illegal activities
- Attacks against critical infrastructure
- Mass exploitation or automated attacks

### Responsible Usage Guidelines

1. **Always obtain written authorization** before conducting security tests
2. **Stay within scope** of authorized testing boundaries
3. **Document all activities** during security assessments
4. **Report vulnerabilities responsibly** through proper disclosure channels
5. **Respect rate limits** and avoid denial-of-service conditions
6. **Protect sensitive data** discovered during testing
7. **Follow applicable laws** and regulations in your jurisdiction

## Why This Project Exists

SecLists is an incredible resource containing over 6,000 files and 4.5GB of security testing data. However, its size and breadth can be overwhelming. This project:

- **Curates essential lists** most commonly needed for security testing
- **Organizes by category** for easy discovery and access
- **Integrates with Claude Code** for seamless workflow integration
- **Provides clear documentation** on when and how to use each resource
- **Emphasizes ethical use** with clear guidelines and warnings

## Source & Attribution

All security testing resources in this repository are sourced from [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler and contributors.

- **Original Repository:** https://github.com/danielmiessler/SecLists
- **License:** MIT License
- **Maintainer:** Daniel Miessler
- **Contributors:** Security community worldwide

This project is a curated, skill-packaged subset for Claude Code integration. For the complete SecLists collection (4.5GB, 6,000+ files), visit the original repository.

## Best Practices

### When Using Password Lists
- Only test against systems you own or have written authorization to test
- Implement rate limiting to avoid account lockouts
- Monitor for defensive responses (WAF blocks, account locks)
- Use appropriate delays between attempts

### When Using Fuzzing Payloads
- Test in isolated environments first
- Validate input sanitization and output encoding
- Check for secondary effects (logs, monitoring alerts)
- Document all findings systematically

### When Using Web Shells
- Only use for detection system validation
- Test in isolated lab environments
- Never deploy on production systems
- Focus on defensive detection capabilities

## Contributing

Contributions are welcome! If you'd like to:

- Add new curated wordlists
- Improve documentation
- Fix errors or update outdated information
- Suggest additional skills

Please open an issue or pull request.

## Documentation and References

- [SecLists Official Repository](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Platforms](https://github.com/disclose/bug-bounty-platforms)
- [Responsible Disclosure Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)

## License

MIT License - Use responsibly with proper authorization.

This is a curated collection and redistribution of SecLists content. The original SecLists project is maintained by Daniel Miessler under the MIT License. All credit for the original content goes to the SecLists project and its contributors.

## Disclaimer

This repository is provided for educational and authorized security testing purposes only. The maintainers of this repository are not responsible for any misuse or damage caused by the resources contained herein. Users are solely responsible for ensuring they have proper authorization before conducting any security testing activities.

---

**Note:** This is a curated reference repository. Always verify you have proper authorization before conducting security testing. When in doubt, ask for explicit written permission.

**Generated with Claude Code** | Awesome Claude Skills: Security Collection
