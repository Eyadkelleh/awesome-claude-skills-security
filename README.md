# Awesome Claude Skills: Security Collection

A curated collection of security testing resources packaged as Claude Code skills, available on [skills.sh](https://skills.sh/)

## Overview

This repository contains a curated collection of security testing resources from [SecLists](https://github.com/danielmiessler/SecLists) packaged as Claude Code skills. These skills provide instant access to essential wordlists, payloads, patterns, and web shells for authorized security testing, penetration testing, CTF competitions, and security research.

The goal of this project is to provide organized, immediately accessible security testing resources that integrate seamlessly with Claude Code workflows for:

- Authorized penetration testing and security assessments
- Bug bounty program research
- CTF competition problem solving
- Security tool development and testing
- Educational security demonstrations
- Vulnerability research in controlled environments

## Quick Start

### Install from skills.sh (Recommended)

The easiest way to get started is to install from the skills.sh marketplace:

```bash
# Add the awesome-security-skills marketplace
/plugin marketplace add Eyadkelleh/awesome-claude-skills-security

# List all available security plugins
/plugin

# Install all security skills at once
/plugin install security-fuzzing@awesome-security-skills
/plugin install security-passwords@awesome-security-skills
/plugin install security-patterns@awesome-security-skills
/plugin install security-payloads@awesome-security-skills
/plugin install security-usernames@awesome-security-skills
/plugin install security-webshells@awesome-security-skills
/plugin install llm-testing@awesome-security-skills
```

### Verify Installation

After installing, verify the skills are available:

```bash
# In Claude Code, try a command
/sqli-test

# Or ask Claude to use a skill
"Use the security-fuzzing skill to show me SQL injection payloads"
```

### What You Get

Once installed, you'll have access to:
- **7 Security Skill Categories**: Fuzzing, Passwords, Patterns, Payloads, Usernames, Web-shells, LLM Testing
- **5 Slash Commands**: `/sqli-test`, `/xss-test`, `/wordlist`, `/webshell-detect`, `/api-keys`
- **3 Specialized Agents**: Pentest Advisor, CTF Assistant, Bug Bounty Hunter
- **Curated SecLists Content**: Essential wordlists and payloads for security testing
- **LLM Security Testing**: Comprehensive AI/ML security testing prompts and methodologies

### First Time Setup

If this is your first time using Claude Code skills:

1. **Make sure you have Claude Code CLI installed**
   ```bash
   # Check if Claude Code is installed
   claude --version
   ```

2. **Add this marketplace**
   ```bash
   /plugin marketplace add Eyadkelleh/awesome-claude-skills-security
   ```

3. **Install your first skill**
   ```bash
   # Start with fuzzing payloads
   /plugin install security-fuzzing@awesome-security-skills
   ```

4. **Test it out**
   ```bash
   # Try a slash command
   /sqli-test

   # Or ask Claude naturally
   "Show me SQL injection payloads from the security-fuzzing skill"
   ```

### Troubleshooting

**"Marketplace not found"**
- Ensure the GitHub repository is public
- Check your internet connection
- Verify the repository name is correct: `Eyadkelleh/awesome-claude-skills-security`

**"Plugin not available"**
- Make sure you've added the marketplace first
- Run `/plugin` to see all available plugins
- Check that you're using the correct plugin name and marketplace

**"Command not working"**
- Verify the plugin is installed with `/plugin`
- Try reinstalling: `/plugin uninstall <plugin-name>` then install again
- Make sure you're using the correct slash command syntax

**Need help?**
- Open an issue on [GitHub](https://github.com/Eyadkelleh/awesome-claude-skills-security/issues)
- Check the [Claude Code documentation](https://docs.anthropic.com/claude-code)

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

### LLM Testing
**Comprehensive AI/ML security testing prompts**
- Bias detection (gender, nationality, race/ethnicity)
- Data leakage and privacy testing
- Memory recall testing
- Alignment and divergence attacks
- Adversarial prompt resistance
- AI safety evaluation

## Requirements

- **Claude Code CLI** (latest version)
- Git for cloning the repository
- Basic understanding of security testing concepts
- Authorization for security testing on target systems

## Installation

### Method 1: Add Marketplace (Recommended)

Add this repository as a Claude Code plugin marketplace:

```bash
/plugin marketplace add Eyadkelleh/awesome-claude-skills-security
```

Then list available plugins:

```bash
/plugin
```

### Method 2: Install Specific Plugins

Install individual security testing plugins:

```bash
# Fuzzing payloads for injection testing
/plugin install security-fuzzing@awesome-security-skills

# Password wordlists
/plugin install security-passwords@awesome-security-skills

# Sensitive data patterns (API keys, etc.)
/plugin install security-patterns@awesome-security-skills

# XSS, XXE, and attack payloads
/plugin install security-payloads@awesome-security-skills

# Username wordlists
/plugin install security-usernames@awesome-security-skills

# Web shell samples for detection
/plugin install security-webshells@awesome-security-skills

# LLM security testing prompts
/plugin install llm-testing@awesome-security-skills
```

### Method 3: Clone Repository

Clone and use directly:

```bash
git clone https://github.com/Eyadkelleh/awesome-claude-skills-security.git
cd awesome-claude-skills-security
```

## Usage

### Using Slash Commands

Once installed from skills.sh, you can use specialized security testing commands directly in Claude Code:

```bash
# SQL injection testing guidance
/sqli-test

# XSS testing and payload generation
/xss-test

# Access wordlists for fuzzing/brute force
/wordlist

# Web shell detection (defensive security)
/webshell-detect

# Scan for exposed API keys and secrets
/api-keys
```

### Using Skills in Natural Language

You can also reference the skills in your conversation with Claude:

```bash
# Ask Claude to use specific skills
"Use the security-fuzzing skill to help me test for SQL injection vulnerabilities"

"Show me common passwords from the security-passwords skill"

"Help me detect exposed API keys using the security-patterns skill"

"I need XSS payloads from the security-payloads skill"
```

### Using Specialized Agents

Invoke expert agents for comprehensive security guidance:

```bash
# Penetration testing advisor
"Use the pentest-advisor agent to help me plan a security assessment"

# CTF competition assistant
"Use the ctf-assistant agent to help me solve this web exploitation challenge"

# Bug bounty hunting advisor
"Use the bug-bounty-hunter agent to help me test this bug bounty program responsibly"
```

### Practical Usage Examples

**Example 1: SQL Injection Testing**
```bash
# Start with the slash command
/sqli-test

# Or ask Claude naturally
"I need to test a login form for SQL injection. Use the security-fuzzing skill to show me relevant payloads"
```

**Example 2: Password Auditing**
```bash
# Access password lists
/wordlist

# Or ask Claude
"Use the security-passwords skill to show me the most common weak passwords to test against our password policy"
```

**Example 3: Code Review for Secrets**
```bash
# Scan for exposed secrets
/api-keys

# Or ask Claude
"Use the security-patterns skill to help me scan this codebase for exposed API keys and credentials"
```

**Example 4: CTF Challenge**
```bash
# Get comprehensive CTF help
"I'm working on a web exploitation CTF challenge. Use the ctf-assistant agent and security-payloads skill to help me approach this"
```

**Example 5: LLM Security Testing**
```bash
# Test for AI model biases
"Use the llm-testing skill to help me test this AI model for gender bias"

# Check for data leakage vulnerabilities
"Use the llm-testing skill to test for data leakage and privacy issues in this LLM"

# Comprehensive AI safety audit
"I need to perform a red team assessment on this LLM. Use the llm-testing skill to show me prompts for bias detection, alignment testing, and adversarial resistance"
```

### Direct File Access

If you cloned the repository, access wordlists directly:

```python
# Example: Load SQL injection payloads
with open('seclists-categories fuzzing/fuzzing/references/Fuzzing/quick-SQLi.txt', 'r') as f:
    sqli_payloads = f.read().splitlines()

# Example: Load common passwords
with open('seclists-categories passwords/passwords/references/500-worst-passwords.txt', 'r') as f:
    passwords = f.read().splitlines()

# Example: Use in security testing
for payload in sqli_payloads[:10]:
    test_injection(target_url, payload)
```

### Example Workflows

**SQL Injection Testing (Authorized)**
```bash
# 1. Start with the SQL injection command
/sqli-test

# 2. Follow the guidance provided
# 3. Use appropriate payloads from fuzzing/references/
# 4. Document all findings
```

**CTF Challenge**
```bash
# 1. Invoke the CTF assistant
"Help me solve this web exploitation CTF challenge"

# 2. Describe the challenge
# 3. Get guidance on approach and payloads
# 4. Access relevant wordlists as suggested
```

**Bug Bounty Hunting**
```bash
# 1. Invoke the bug bounty agent
"Help me test this bug bounty program"

# 2. Review scope and methodology
# 3. Use appropriate testing commands
# 4. Get guidance on responsible disclosure
```

## Project Structure

```
awesome-claude-skills-security/
├── README.md                                    # This file
├── .claude-plugin/                              # Plugin marketplace configuration
│   ├── marketplace.json                         # Marketplace definition
│   ├── plugin.json                              # Main plugin manifest
│   ├── commands/                                # Slash commands
│   │   ├── sqli-test.md                        # SQL injection testing
│   │   ├── xss-test.md                         # XSS testing
│   │   ├── wordlist.md                         # Wordlist access
│   │   ├── webshell-detect.md                  # Web shell detection
│   │   └── api-keys.md                         # API key scanning
│   └── agents/                                  # Specialized agents
│       ├── pentest-advisor.md                  # Pentesting guidance
│       ├── ctf-assistant.md                    # CTF competition help
│       └── bug-bounty-hunter.md                # Bug bounty guidance
├── seclists-categories/
│   ├── fuzzing/fuzzing/
│   │   ├── SKILL.md                            # Skill metadata
│   │   └── references/                         # SQL/NoSQL/Command injection
│   ├── passwords/passwords/
│   │   ├── SKILL.md
│   │   └── references/                         # Password wordlists
│   ├── pattern-matching/pattern-matching/
│   │   ├── SKILL.md
│   │   └── references/                         # API keys, sensitive data
│   ├── payloads/payloads/
│   │   ├── SKILL.md
│   │   └── references/                         # XSS, XXE, file upload
│   ├── usernames/usernames/
│   │   ├── SKILL.md
│   │   └── references/                         # Username wordlists
│   └── web-shells/web-shells/
│       ├── SKILL.md
│       └── references/                         # Web shell samples
```

## Features

### Slash Commands

- **`/sqli-test`** - Interactive SQL injection testing guide with payload recommendations
- **`/xss-test`** - XSS vulnerability testing with context-aware payload suggestions
- **`/wordlist`** - Quick access to curated wordlists for authorized testing
- **`/webshell-detect`** - Defensive security guidance for web shell detection
- **`/api-keys`** - Scan for exposed API keys and sensitive credentials

### Specialized Agents

- **Pentest Advisor** - Strategic penetration testing methodology and planning
- **CTF Assistant** - CTF competition challenge solver with educational focus
- **Bug Bounty Hunter** - Professional bug bounty hunting and responsible disclosure

### Security Resources

- **7 Plugin Categories** - Fuzzing, Passwords, Patterns, Payloads, Usernames, Web-shells, LLM Testing
- **Curated from SecLists** - Essential security testing wordlists and payloads
- **AI/ML Security Testing** - Comprehensive LLM testing prompts for bias, alignment, and safety
- **Instant Access** - All resources available through Claude Code commands
- **Ethical Guidelines** - Built-in reminders for authorized use only

## Security & Ethics

### Authorized Use Cases

- Authorized penetration testing with written permission
- Bug bounty programs (within documented scope)
- CTF competitions and challenges
- Security research in controlled lab environments
- Testing your own systems and applications
- Educational demonstrations with proper safeguards
- Defensive security tool development
- AI/ML security research and red team operations
- LLM safety evaluation and bias testing
- Responsible AI development and testing

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

## How to Use This on skills.sh

This skill collection is designed to work with the skills.sh marketplace for Claude Code. Here's how users can find and install it:

### For Users

1. **Browse skills.sh**: Visit [skills.sh](https://skills.sh/) to discover this and other skills
2. **Add the marketplace**: Use `/plugin marketplace add Eyadkelleh/awesome-claude-skills-security`
3. **Install skills**: Choose individual skills or install all at once
4. **Start using**: Access wordlists, commands, and agents immediately

### For Contributors

Want to add your own skills to this collection? Here's how:

1. **Fork this repository**
2. **Add your skill** in the appropriate category under `seclists-categories/`
3. **Create a SKILL.md** file with metadata and references
4. **Update marketplace.json** to include your skill
5. **Submit a pull request** with a description of your contribution

### Publishing Your Own Skills

To create your own skill collection for skills.sh:

1. **Create a repository** with a `.claude-plugin/` directory
2. **Add marketplace.json** with your plugin definitions (see ours as an example)
3. **Include SKILL.md files** in each skill directory
4. **Push to GitHub** and make it public
5. **Share your marketplace** - users can add it with `/plugin marketplace add username/repo-name`

Example `marketplace.json` structure:
```json
{
  "name": "your-marketplace-name",
  "owner": {
    "name": "Your Name",
    "email": "your@email.com"
  },
  "metadata": {
    "description": "Your skill collection description",
    "version": "1.0.0",
    "pluginRoot": "./skills"
  },
  "plugins": [
    {
      "name": "your-skill-name",
      "source": "./path/to/skill",
      "description": "Skill description",
      "version": "1.0.0",
      "keywords": ["tag1", "tag2"],
      "category": "your-category"
    }
  ]
}
```

## Documentation and References

- [skills.sh Marketplace](https://skills.sh/) - Browse and discover Claude Code skills
- [Claude Code Documentation](https://docs.anthropic.com/claude-code) - Official Claude Code docs
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
