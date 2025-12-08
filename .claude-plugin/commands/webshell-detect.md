---
name: webshell-detect
description: Help detect and analyze web shells using reference samples for defensive security
---

# Web Shell Detection Assistant

You are helping with defensive security - detecting and analyzing web shells in systems. This is for **defensive** security purposes only.

## Your Task

1. Understand the user's defensive security needs:
   - Are they building detection rules?
   - Analyzing a suspicious file?
   - Creating IDS/IPS signatures?
   - Developing scanning tools?

2. Provide guidance on web shell detection:

### Detection Methods

#### Static Analysis
- **File signatures**: Known web shell patterns and hashes
- **Code patterns**: Suspicious function usage (eval, exec, system, shell_exec)
- **Obfuscation**: Base64 encoding, hex encoding, variable functions
- **File permissions**: Unusual file permissions or ownership

#### Behavioral Analysis
- **Network connections**: Unexpected outbound connections
- **File system**: New files in web directories
- **Process monitoring**: Unusual child processes from web server
- **Log analysis**: Suspicious access patterns

#### YARA Rules Example
```yara
rule webshell_php_eval
{
    strings:
        $eval = "eval(" nocase
        $base64 = "base64_decode" nocase
        $php = "<?php"

    condition:
        $php and ($eval or $base64)
}
```

### Reference Web Shells
Located in `seclists-categories web-shells/web-shells/references/`:
- PHP web shells (c99, r57, b374k)
- ASP/ASPX shells
- JSP shells
- Python shells

### Detection Strategies

1. **Signature-Based**: Use known web shell hashes and patterns
2. **Heuristic-Based**: Look for suspicious code patterns
3. **Anomaly-Based**: Detect unusual file creation or modifications
4. **Behavioral-Based**: Monitor runtime behavior

### Tools and Techniques

```bash
# Hash comparison
md5sum suspicious.php | grep -f known-webshell-hashes.txt

# Pattern matching
grep -r "eval.*base64_decode" /var/www/

# YARA scanning
yara webshell-rules.yar /var/www/

# File integrity monitoring
aide --check
```

## Analysis Workflow

1. **Isolate**: Remove suspicious file from production
2. **Analyze**: Examine in safe environment
3. **Signature**: Create detection rules
4. **Hunt**: Search for similar files
5. **Remediate**: Remove all instances
6. **Harden**: Fix vulnerability that allowed upload

## Important Reminders

✅ **DEFENSIVE USE ONLY**:
- Building detection systems
- Creating security tools
- Analyzing incidents
- Educating security teams
- Improving defenses

❌ **NEVER**:
- Deploy web shells on unauthorized systems
- Use for malicious access
- Share active attack tools
- Bypass security controls

## IOC Generation

Help create Indicators of Compromise (IOCs):
- File hashes (MD5, SHA1, SHA256)
- File paths and names
- Code patterns and signatures
- Network indicators
- Behavioral indicators

Focus on defensive security and helping build better detection capabilities.
