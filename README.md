# 🔒 Privacy

> **Windows Privacy Hardering Toolkit** - Comprehensive privacy protection and telemetry reduction system.

---

## 📋 Overview

Privacy is a comprehensive Windows privacy hardening toolkit that reduces telemetry, disables tracking features, and enhances user privacy through registry modifications and system tweaks.

---

## 🎯 Features

- 🚫 **Telemetry Reduction** - Disable Windows data collection
- 🕵️ **Tracking Prevention** - Block analytics and usage tracking
- 📡 **Data Transmission** - Stop unwanted data uploads
- 🔧 **Registry Hardening** - Privacy-focused registry settings
- ⚡ **Modular Design** - Choose components to apply
- 🔄 **Reversible** - Can restore default settings

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `Generator.ps1` | Privacy configuration generator (10.6 KB) |
| `Privacy.cmd` | Compiled privacy hardening executable (5.6 MB) |
| `Privacy.reg` | Registry entries for privacy (147 KB) |
| `source` | Source files for generator (6.5 MB) |

---

## 🚀 Usage

### Quick Apply
```cmd
:: Run as Administrator
Privacy.cmd
```

### Generate Custom Config
```powershell
# Modify settings in Generator.ps1
.\Generator.ps1
```

### Registry Only
```cmd
:: Import registry entries
reg import Privacy.reg
```

---

## 📋 Privacy Areas Covered

| Category | Description |
|------------|-------------|
| **Telemetry** | Disable diagnostic data collection |
| **Advertising** | Turn off advertising ID and targeting |
| **Location** | Disable location tracking |
| **Speech** | Turn off speech recognition data |
| **Ink/Typing** | Disable typing and handwriting collection |
| **Activity History** | Clear and disable timeline |
| **Cortana** | Disable Cortana and search data |
| **Windows Update** | Configure update privacy settings |
| **App Permissions** | Restrict app access to sensitive data |
| **Network** | Disable Wi-Fi sense and hotspot sharing |

---

## ⚙️ Generator Features

The `Generator.ps1` script can customize:
- Which privacy areas to harden
- Aggressiveness level
- Keep vs disable specific features
- Create reversible backup

---

## ⚠️ Important Notes

### ⚠️ System Impact
- Some Windows features may be limited
- OneDrive/Office integration may be affected
- Windows Store may have reduced functionality

### 🔧 Restore Defaults
```cmd
:: Use system restore point created by script
:: Or manually re-enable features in Settings
```

---

## 📝 Requirements

- Windows 10/11
- Administrator privileges
- System Restore recommended before running

---

## 📜 License & Disclaimer
---

## Comprehensive legal disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided "AS IS", without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are not liable for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>