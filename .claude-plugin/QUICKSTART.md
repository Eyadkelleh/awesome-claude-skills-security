# Quick Start Guide

## Installation

### Add the Marketplace

```bash
/plugin marketplace add Eyadkelleh/awesome-claude-skills-security
```

### Browse Available Plugins

```bash
/plugin
```

### Install All Security Plugins

```bash
/plugin install security-fuzzing@awesome-security-skills
/plugin install security-passwords@awesome-security-skills
/plugin install security-patterns@awesome-security-skills
/plugin install security-payloads@awesome-security-skills
/plugin install security-usernames@awesome-security-skills
/plugin install security-webshells@awesome-security-skills
```

## Available Commands

### Security Testing Commands

```bash
/sqli-test          # SQL injection testing guidance
/xss-test           # XSS vulnerability testing
/wordlist           # Access SecLists wordlists
/webshell-detect    # Web shell detection (defensive)
/api-keys           # Scan for exposed credentials
```

## Available Agents

Ask Claude Code to use these specialized agents:

- **pentest-advisor** - For penetration testing methodology and strategy
- **ctf-assistant** - For CTF competition challenges
- **bug-bounty-hunter** - For bug bounty programs and responsible disclosure

## Example Usage

### SQL Injection Testing

```bash
# Start with the command
/sqli-test

# Follow the interactive guidance
# Access payloads from: seclists-categories fuzzing/fuzzing/references/Fuzzing/
```

### Bug Bounty Hunting

```
"I need help testing a bug bounty program. Use the bug-bounty-hunter agent."

Then describe your target and scope.
```

### CTF Challenge

```
"Help me solve this web CTF challenge using the ctf-assistant agent."

Describe the challenge and get strategic guidance.
```

## Security Resources

### Fuzzing Payloads
- SQL injection: `quick-SQLi.txt`, `Generic-SQLi.txt`
- NoSQL injection: `NoSQL.txt`
- Command injection: `command-injection-commix.txt`
- LDAP injection: `LDAP.txt`

### Passwords
- Common: `500-worst-passwords.txt`, `10k-most-common.txt`
- Leaked: Various breach compilations
- Probable: `probable-v2-top*.txt`

### Payloads
- XSS vectors
- XXE exploitation
- Template injection
- File upload bypasses

### Patterns
- API keys (AWS, Google, GitHub)
- Credit card formats
- Email addresses
- IP addresses

### Usernames
- Default accounts
- Common names
- Service-specific accounts

### Web Shells (Defensive)
- PHP shells
- ASP/ASPX shells
- JSP shells
- Detection patterns

## Important Reminders

⚠️ **CRITICAL**: Only use for:
- Authorized penetration testing with written permission
- Bug bounty programs within documented scope
- CTF competitions and challenges
- Testing your own systems
- Educational purposes in controlled environments

❌ **NEVER**:
- Test unauthorized systems
- Violate terms of service
- Access personal data unnecessarily
- Ignore rate limits or cause DoS
- Share vulnerabilities before responsible disclosure

## Getting Help

- Read command documentation: Each slash command has built-in guidance
- Use specialized agents: They provide comprehensive methodology
- Check SecLists documentation: https://github.com/danielmiessler/SecLists
- Responsible disclosure: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html

## Support

- GitHub Issues: https://github.com/Eyadkelleh/awesome-claude-skills-security/issues
- Original SecLists: https://github.com/danielmiessler/SecLists

---

**Remember**: Always obtain proper authorization before conducting any security testing!
