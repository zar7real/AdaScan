# 🔍 AdaScan - Advanced Network Security Assessment Tool

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-assessment-red.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macOS-lightgrey.svg)]()

> **A comprehensive network security assessment tool that combines device discovery, service enumeration, and vulnerability analysis in a single, elegant solution.**

AdaScan is a powerful Python-based security assessment tool designed for cybersecurity professionals, penetration testers, and network administrators. It automates the process of network reconnaissance, service detection, and vulnerability identification while providing detailed, actionable reports.

## ✨ Features

### 🎯 **Core Capabilities**
- **Intelligent Device Discovery** - Automated network scanning with nmap integration
- **Service Enumeration** - Deep analysis of running services and versions
- **Vulnerability Assessment** - Real-time CVE database lookups via NVD API
- **Exploit Intelligence** - Public exploit search through Shodan integration
- **Multi-format Reporting** - JSON, CSV, and TXT output formats

### 🚀 **Advanced Features**
- **Progress Tracking** - Real-time progress bars with ETA calculations
- **Colored Output** - Beautiful terminal interface with severity-based color coding
- **Rate Limiting** - Built-in API rate limiting to prevent service disruption
- **Flexible Configuration** - JSON-based configuration with command-line overrides
- **Comprehensive Logging** - Detailed logging for audit trails and debugging

### 🛡️ **Security-First Design**
- **CVSS Scoring** - Automatic vulnerability severity assessment
- **Exploit Correlation** - Links CVEs to available public exploits
- **Risk Prioritization** - Severity-based vulnerability ranking
- **Professional Reporting** - Enterprise-ready vulnerability reports

## 📋 Requirements

### System Requirements
- **Python 3.6+**
- **Linux, Windows, or macOS**
- **Network access** for API calls

### Dependencies

#### Required
```bash
pip install requests
```

#### Optional (Recommended)
```bash
pip install python-nmap shodan
```

> **Note:** Without optional dependencies, AdaScan will use fallback methods with limited functionality.

## ⚡ Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/zar7real/AdaScan.git
cd AdaScan

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x adascan.py
```

### 2. Basic Usage

```bash
# Scan a single IP
python3 adascan.py 192.168.1.1

# Scan a network range
python3 adascan.py 192.168.1.0/24

# Scan with custom output
python3 adascan.py 192.168.1.1 -o my_report.json
```

### 3. First Run Output

```
 $$$$$$\        $$\          $$$$$$\                               
$$  __$$\       $$ |        $$  __$$\                              
$$ /  $$ | $$$$$$$ | $$$$$$\ $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  
$$$$$$$$ |$$  __$$ | \____$$\ \$$$$$$\ $$  _____|\____$$\ $$  __$$\ 
$$  __$$ |$$ /  $$ | $$$$$$$ | \____$$\ $$ /     $$$$$$$ |$$ |  $$ |
$$ |  $$ |$$ |  $$ |$$  __$$ |$$\   $$ |$$ |    $$  __$$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |\$$$$$$$ |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\__|  \__| \_______| \_______| \______/  \_______|\_______|\__|  \__|

         Advanced Network Security Assessment Tool v1.0
         Developed by Alchemy Security Division

[+] PHASE 1: DEVICE DISCOVERY
Scanning 192.168.1.0/24...
✓ Discovery completed. Found 5 devices

[+] PHASE 2: DEEP ANALYSIS
Deep scanning 192.168.1.1 (1/5)
Services detected on 192.168.1.1:
Port      Protocol  Service        Version
22        tcp       ssh            OpenSSH 7.4
80        tcp       http           Apache httpd 2.4.6
443       tcp       https          Apache httpd 2.4.6

[+] VULNERABILITY ASSESSMENT
Searching vulnerabilities for 192.168.1.1...
Analyzing services: |████████████████████████████████████████████████| 100%

Vulnerabilities found for 192.168.1.1:
CVE ID          Service        Severity  CVSS  Description
CVE-2016-10009  ssh            HIGH      7.5   Untrusted search path vulnerability...
CVE-2017-7679   http           MEDIUM    5.0   In Apache HTTP Server versions...

✓ Report generated successfully: adascan_report_20241201_143052.json
✓ Scan completed successfully in 45.2 seconds
```

## 🔧 Configuration

### Configuration File Setup

Generate a sample configuration file:

```bash
python3 adascan.py --create-config
```

This creates `adascan_config.json`:

```json
{
    "shodan_api_key": "",
    "nvd_api_key": "",
    "scan_timeout": 300,
    "max_devices": 100,
    "output_format": "json",
    "scan_ports": "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
}
```

### API Keys Configuration

#### NVD API Key (Recommended)
1. Visit [NVD API](https://nvd.nist.gov/developers/request-an-api-key)
2. Request an API key
3. Add to configuration: `"nvd_api_key": "your-api-key-here"`

**Benefits:**
- Higher rate limits (50 requests/30 seconds vs 5/30 seconds)
- More comprehensive vulnerability data
- Faster scanning

#### Shodan API Key (Optional)
1. Create account at [Shodan.io](https://shodan.io)
2. Get API key from account dashboard
3. Add to configuration: `"shodan_api_key": "your-api-key-here"`

**Benefits:**
- Public exploit search capability
- Enhanced threat intelligence
- Real-world exploitation data

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `shodan_api_key` | `""` | Shodan API key for exploit search |
| `nvd_api_key` | `""` | NVD API key for enhanced rate limits |
| `scan_timeout` | `300` | Maximum scan time in seconds |
| `max_devices` | `100` | Maximum devices to scan |
| `output_format` | `"json"` | Report format (json/csv/txt) |
| `scan_ports` | `"21-23,25,53..."` | Ports to scan |

## 🎯 Usage Examples

### Basic Scanning

```bash
# Single IP scan
python3 adascan.py 10.0.0.1

# Network range scan
python3 adascan.py 192.168.1.0/24

# IP range scan
python3 adascan.py -t 10.0.0.1-10.0.0.50
```

### Advanced Options

```bash
# Custom port specification
python3 adascan.py 192.168.1.1 -p 22,80,443,3389

# Different output formats
python3 adascan.py 192.168.1.1 -f csv -o vulnerabilities.csv
python3 adascan.py 192.168.1.1 -f txt -o report.txt

# Verbose logging
python3 adascan.py 192.168.1.1 -v

# Custom configuration
python3 adascan.py 192.168.1.1 -c custom_config.json

# Disable colored output
python3 adascan.py 192.168.1.1 --no-color
```

### Production Scanning

```bash
# Large network with custom limits
python3 adascan.py 10.0.0.0/16 --max-devices 500 --timeout 600

# Comprehensive port scan
python3 adascan.py 192.168.1.1 -p 1-65535 -f json -o full_scan.json

# Quick service discovery
python3 adascan.py 192.168.1.0/24 -p 22,80,443 --timeout 60
```

## 📊 Report Formats

### JSON Report
Structured data perfect for integration and analysis:

```json
{
  "scan_info": {
    "timestamp": "2024-12-01T14:30:52.123456",
    "tool": "AdaScan v1.0",
    "total_devices": 5
  },
  "devices": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "os": "Linux 3.2 - 4.9",
      "services": {
        "22": {
          "protocol": "tcp",
          "name": "ssh",
          "version": "OpenSSH 7.4"
        }
      },
      "vulnerabilities": [
        {
          "id": "CVE-2016-10009",
          "severity": "HIGH",
          "cvss_score": 7.5,
          "description": "Untrusted search path vulnerability...",
          "service": "ssh",
          "exploits": [...]
        }
      ]
    }
  ]
}
```

### CSV Report
Tabular format for spreadsheet analysis:

| IP | Hostname | OS | Service | CVE ID | Severity | CVSS | Description |
|----|----------|----|---------| -------|----------|------|-------------|
| 192.168.1.1 | router.local | Linux | ssh | CVE-2016-10009 | HIGH | 7.5 | Untrusted search path... |

### TXT Report
Human-readable format for documentation:

```
AdaScan - VULNERABILITY REPORT
==================================================
Date: 2024-12-01 14:30:52
Total scanned devices: 1

Device: 192.168.1.1
Hostname: router.local
OS: Linux 3.2 - 4.9

Detected services:
------------------------------
  - Port 22/tcp: ssh OpenSSH 7.4
  - Port 80/tcp: http Apache httpd 2.4.6

Vulnerabilities (2):
------------------------------
  - CVE-2016-10009 (HIGH, CVSS: 7.5)
    Service: ssh OpenSSH 7.4
    Description: Untrusted search path vulnerability...
    Available exploits: 3
```

## 🎨 Color Coding

AdaScan uses intelligent color coding for quick visual assessment:

- 🔴 **CRITICAL** - White text on red background (CVSS 9.0-10.0)
- 🟠 **HIGH** - Bright red text (CVSS 7.0-8.9)
- 🟡 **MEDIUM** - Yellow text (CVSS 4.0-6.9)
- 🟢 **LOW** - Green text (CVSS 0.1-3.9)
- 🔵 **INFO** - Blue text (Informational)

## 📈 Performance Optimization

### Rate Limiting
AdaScan includes built-in rate limiting to prevent API throttling:

- **NVD API**: 0.5 second delay between requests
- **Shodan API**: 0.5 second delay between requests
- **Automatic retry** on rate limit responses

### Scanning Optimization

```bash
# For large networks, use targeted port scanning
python3 adascan.py 10.0.0.0/16 -p 22,80,443 --max-devices 200

# Use configuration file for consistent settings
python3 adascan.py -c production_config.json large_network.txt
```

### Memory Usage
- **Streaming processing** for large networks
- **Configurable device limits** to control memory usage
- **Efficient data structures** for vulnerability storage

## 🔒 Security Considerations

### Ethical Usage
- **Only scan networks you own or have explicit permission to test**
- **Respect rate limits** and terms of service for external APIs
- **Use responsibly** in production environments

### API Key Security
```bash
# Set environment variables instead of config files
export NVD_API_KEY="your-key-here"
export SHODAN_API_KEY="your-key-here"

# Restrict config file permissions
chmod 600 adascan_config.json
```

### Network Impact
- AdaScan uses **non-intrusive scanning techniques**
- **Configurable timeouts** prevent network congestion
- **Respectful rate limiting** minimizes service impact

## 🔍 Troubleshooting

### Common Issues

#### "nmap not available" Warning
```bash
# Install python-nmap
pip install python-nmap

# Or install nmap system package
# Ubuntu/Debian: sudo apt-get install nmap
# CentOS/RHEL: sudo yum install nmap
# macOS: brew install nmap
```

#### Rate Limiting Errors
```bash
# Get NVD API key for higher limits
python3 adascan.py --create-config
# Edit adascan_config.json with your API key
```

#### Permission Errors
```bash
# Run with appropriate permissions
sudo python3 adascan.py 192.168.1.0/24

# Or adjust scan parameters
python3 adascan.py 192.168.1.1 -p 80,443  # Non-privileged ports only
```

### Debug Mode
```bash
# Enable verbose logging
python3 adascan.py 192.168.1.1 -v

# Check log file
tail -f adascan.log
```

### Performance Issues
```bash
# Reduce scan scope
python3 adascan.py 192.168.1.1 --max-devices 50 --timeout 120

# Target specific services
python3 adascan.py 192.168.1.1 -p 22,80,443
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
git clone https://github.com/zar7real/AdaScann.git
cd AdaScan
python -m pytest tests/
```

### Reporting Issues
Please use the [GitHub Issues](https://github.com/zar7real/AdaScan/issues) page to report bugs or request features.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NVD (National Vulnerability Database)** for vulnerability data
- **Shodan** for exploit intelligence
- **nmap** for network scanning capabilities
- **The cybersecurity community** for continuous feedback and improvement

## 📞 Support

- 📧 **Email**: None
- 🐛 **Issues**: [GitHub Issues](https://github.com/zar7real/AdaScan/issues)
- 📖 **Documentation**: [Wiki](https://github.com/zar7real/AdaScan/wiki)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/zar7real/AdaScan/discussions)

---

<div align="center">

**Made with ❤️ by the Alchemy Security Division**

[![GitHub stars](https://img.shields.io/github/stars/zar7real/AdaScan.svg?style=social&label=Star)](https://github.com/zar7real/AdaScan)
[![GitHub forks](https://img.shields.io/github/forks/zar7real/AdaScan.svg?style=social&label=Fork)](https://github.com/zar7real/AdaScan/fork)

*Empowering cybersecurity professionals with advanced network assessment capabilities*

</div>
