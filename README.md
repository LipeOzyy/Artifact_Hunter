![alt image](/img/one.jpg)
![alt image](/img/2.jpg)

# Artifact_Hunter
Artifact Hunter is a command-line tool designed for static analysis of suspicious files, focusing on detecting web shells, malware artifacts, and common obfuscation techniques. The tool performs automated analysis including hash generation, entropy measurement, string extraction, pattern detection, and YARA scanning. Its goal is to support cybersecurity research and help analysts better understand how malicious or heavily obfuscated code behaves in real-world scenarios.

## Multi-Module Analysis Pipeline
```
sample.php
   ↓
hash analysis      (MD5, SHA1, SHA256)
   ↓
strings extraction (ASCII string recovery)
   ↓
entropy analysis   (detect packed/encrypted content)
   ↓
webshell detection (dangerous functions & patterns)
   ↓
obfuscation detection (encoding techniques)
   ↓
YARA scan          (rule-based detection)
   ↓
risk scoring       (threat level assessment)
   ↓
detailed report    (actionable insights)
```
![alt image](https://i.pinimg.com/736x/a8/31/0e/a8310e63393e3bde6f58fc9380271659.jpg)
## Important:

- Never execute untrusted files during analysis
- This tool performs static analysis only - no code execution
- Use in isolated environment for suspected malware
- Keep YARA rules updated for latest threats
- Sanitize file paths to prevent directory traversal





