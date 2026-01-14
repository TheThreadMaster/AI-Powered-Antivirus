# YARA Rules for AI Shield

This directory contains YARA rules for pattern-based malware detection.

## Current Rules

- **malware.yar**: Comprehensive set of malware detection rules including:
  - PowerShell encoded commands
  - Process injection techniques
  - Registry persistence mechanisms
  - Network exfiltration patterns
  - Base64 obfuscation
  - Script execution patterns
  - Anti-analysis techniques
  - Crypto ransomware indicators
  - Keylogger detection
  - File encryption patterns

## Adding Custom Rules

You can add your own YARA rules by:
1. Creating a new `.yar` file in this directory
2. The rules will be automatically loaded by the anomaly detection system

## YARA Rule Format

YARA rules follow this structure:
```yara
rule RuleName {
    meta:
        description = "Rule description"
        severity = "high|medium|low"
    strings:
        $string1 = "pattern" ascii nocase
        $string2 = /regex/ ascii
    condition:
        any of them
}
```

For more information, see: https://yara.readthedocs.io/

