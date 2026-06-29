# 🛡️ MalRev YARA Detection Rules

> YARA detection rules specifically developed to detect the **MalRev Linux Ransomware** family based on reverse engineering analysis.

![YARA](https://img.shields.io/badge/YARA-Rules-red)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 📖 Overview

This repository contains YARA rules created from the reverse engineering process of **MalRev Linux Ransomware**.

Unlike generic signatures, these rules focus on identifying:

- Encryption API usage
- Obfuscated strings
- Broken filesystem artifacts
- Anti-VM indicators
- ELF executable validation

The rules are designed to detect malware samples even after simple string obfuscation techniques have been applied.

---

## 🔗 Related Project

This repository is part of the **MalRev Malware Analysis Project**.

### Reverse Engineering Repository

👉 https://github.com/marckdekeyn-source/MalRev-Reverse-Engineering

The Reverse Engineering project contains:

- Static Analysis
- Dynamic Analysis
- Ghidra Project
- Binary Analysis
- Function Analysis
- Malware Behavior
- IOC Extraction
- Screenshots
- Technical Report

This repository provides the YARA signatures generated from those findings.

```
MalRev-Reverse-Engineering
            │
            │ Reverse Engineering
            ▼
 IOC Extraction
            │
            ▼
     YARA Rules
            │
            ▼
 Malware Detection
```

---

# Detection Logic

Current rule:

```
Linux_Ransomware_Malrev_Obfuscated
```

Detection is based on several indicators simultaneously.

### 1. ELF Validation

The rule first verifies the sample is a Linux ELF executable.

```yara
uint32(0) == 0x464c457f
```

---

### 2. Cryptographic API

Looks for OpenSSL AES-GCM encryption usage.

```text
EVP_aes_128_gcm
```

---

### 3. Obfuscated Strings

MalRev intentionally modifies strings by inserting additional characters.

Examples:

| Original | Obfuscated |
|-----------|------------|
| VirtualBox | VirtualBH |
| VMware | VMwa |
| /.dockerenv | /.dockerH |

These artifacts help detect modified malware variants.

---

### 4. Broken System Paths

The malware also leaves partially corrupted Linux paths.

Examples:

```text
/sys/claH
id/produH
```

---

### Detection Condition

The rule triggers when:

- ELF executable
- AES-GCM encryption API exists
- At least one obfuscated string **or**
- At least one broken system path

This significantly reduces false positives.

---

# Rule

```yara
rule Linux_Ransomware_Malrev_Obfuscated {
    meta:
        description = "Detect MalRev Linux Ransomware (Obfuscated Variant)"
        author = "Marck & Salvado"
        date = "2026"
        severity = "Critical"

    strings:
        $crypto = "EVP_aes_128_gcm"

        $obf_vm1 = "VirtualBH"
        $obf_vm2 = "VMwa"
        $obf_doc = "/.dockerH"

        $broken_path1 = "/sys/claH"
        $broken_path2 = "id/produH"

    condition:
        uint32(0) == 0x464c457f and
        $crypto and
        (1 of ($obf_*) or 1 of ($broken_path*))
}
```

---

# Usage

Install YARA:

Ubuntu

```bash
sudo apt install yara
```

Run the rule against a sample:

```bash
yara Linux_Ransomware_Malrev_Obfuscated.yar sample
```

Recursive scan:

```bash
yara -r Linux_Ransomware_Malrev_Obfuscated.yar /samples
```

Display matching strings:

```bash
yara -s Linux_Ransomware_Malrev_Obfuscated.yar sample
```

---

# Detection Example

```
$ yara Linux_Ransomware_Malrev_Obfuscated.yar malrev

Linux_Ransomware_Malrev_Obfuscated malrev
0x10F3: EVP_aes_128_gcm
0x1A44: VirtualBH
```

---

# Repository Structure

```
YaraRule_MalRev_Detection
│
├── README.md
├── LICENSE
├── rules/
│   └── Linux_Ransomware_Malrev_Obfuscated.yar
│
├── samples/
│   └── README.md
│
└── screenshots/
```

---

# Features

- Linux ELF detection
- OpenSSL encryption detection
- Obfuscated string detection
- Anti-VM artifact detection
- Broken path detection
- Low false positive rate
- Reverse engineering based signatures

---

# Future Rules

Planned additions include:

- Generic MalRev Detection
- Packed Variant Detection
- UPX Packed Variant
- Anti-Debug Variant
- Anti-VM Variant
- Persistence Detection
- IOC-based Detection
- Multi-Family Linux Ransomware Detection

---

# Research Workflow

```text
Malware Sample
      │
      ▼
Reverse Engineering
      │
      ▼
Function Analysis
      │
      ▼
IOC Extraction
      │
      ▼
YARA Rule Development
      │
      ▼
Testing
      │
      ▼
Detection Validation
```

---

# Author

**Marck**

Cyber Security Researcher

Specializing in:

- Malware Analysis
- Reverse Engineering
- Digital Forensics
- Detection Engineering
- Linux Security

---

# Acknowledgements

This project was developed as part of the **MalRev Reverse Engineering Research Project**, where malware behavior was analyzed and transformed into practical YARA signatures for threat detection.

Reverse Engineering Repository:

https://github.com/marckdekeyn-source/MalRev-Reverse-Engineering

---

# License

MIT License

---

⭐ If you find this project useful, consider giving both repositories a star.

- ⭐ MalRev Reverse Engineering
- ⭐ MalRev YARA Detection
