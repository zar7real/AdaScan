#!/usr/bin/env python3
"""
AdaScan - Advanced Network Security Assessment Tool
Developed by Alchemy Security Division

Usage: python3 adascan.py [options]
"""

import sys
import argparse
import logging
import json
import re
import requests
import socket
import csv
import time
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

# Try to import optional dependencies
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Severity-specific colors
    CRITICAL = '\033[41m\033[37m'  # White on red background
    HIGH = '\033[91m'              # Bright red
    MEDIUM = '\033[93m'            # Yellow
    LOW = '\033[92m'               # Green
    
    @staticmethod
    def severity_color(severity):
        if not severity:
            return Colors.BLUE
        severity = severity.upper()
        color_map = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH": Colors.HIGH,
            "MEDIUM": Colors.MEDIUM,
            "LOW": Colors.LOW
        }
        return color_map.get(severity, Colors.BLUE)

# ASCII Art Banner
BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
 $$$$$$\        $$\            $$$$$$\                               
$$  __$$\       $$ |          $$  __$$\                              
$$ /  $$ | $$$$$$$ | $$$$$$\  $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  
$$$$$$$$ |$$  __$$ | \____$$\ \$$$$$$\  $$  _____|\____$$\ $$  __$$\ 
$$  __$$ |$$ /  $$ | $$$$$$$ | \____$$\ $$ /      $$$$$$$ |$$ |  $$ |
$$ |  $$ |$$ |  $$ |$$  __$$ |$$\   $$ |$$ |     $$  __$$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |\$$$$$$$ |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\__|  \__| \_______| \_______| \______/  \_______|\_______|\__|  \__|
                                                                     
{Colors.ENDC}{Colors.BLUE}
         Advanced Network Security Assessment Tool v1.0
         Developed by Alchemy Security Division
{Colors.ENDC}
"""

# Configure logger
def setup_logger():
    """Setup logging configuration"""
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    
    # Create logger
    logger = logging.getLogger("AdaScan")
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler
    try:
        file_handler = logging.FileHandler("adascan.log")
        file_handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create log file: {e}")
    
    # Console handler with colors
    console_handler = ColoredConsoleHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(console_handler)
    
    return logger

class ColoredConsoleHandler(logging.StreamHandler):
    """Custom handler with colors for console output"""
    def emit(self, record):
        try:
            if record.levelno >= logging.ERROR:
                color = Colors.RED
            elif record.levelno >= logging.WARNING:
                color = Colors.YELLOW
            elif record.levelno >= logging.INFO:
                color = Colors.GREEN
            else:
                color = Colors.BLUE
            
            # Create a copy to avoid modifying the original record
            record_copy = logging.makeLogRecord(record.__dict__)
            record_copy.msg = f"{color}{record_copy.msg}{Colors.ENDC}"
            super().emit(record_copy)
        except Exception:
            super().emit(record)

logger = setup_logger()

@dataclass
class DeviceInfo:
    """Class to store information about scanned devices"""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    vendor: Optional[str] = None
    services: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    versions: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

class ProgressBar:
    """Class to show an animated progress bar"""
    def __init__(self, total, prefix='', suffix='', length=50, fill='█'):
        self.total = max(total, 1)  # Avoid division by zero
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.start_time = time.time()
        self.current = 0
        
    def update(self, current=None):
        if current is not None:
            self.current = min(current, self.total)  # Cap at total
        else:
            self.current = min(self.current + 1, self.total)
            
        percent = self.current / self.total
        filled_length = int(self.length * percent)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        elapsed_time = time.time() - self.start_time
        if percent > 0 and elapsed_time > 0:
            estimated_total = elapsed_time / percent
            remaining = max(0, estimated_total - elapsed_time)
            time_info = f" | ETA: {int(remaining)}s"
        else:
            time_info = ""
            
        sys.stdout.write(f'\r{self.prefix} |{Colors.BLUE}{bar}{Colors.ENDC}| {int(percent*100)}%{self.suffix}{time_info}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            print()

class VulnerabilityScanner:
    """Main scanner to identify devices and search for vulnerabilities"""
    
    def __init__(self, config_file=None):
        """Initialize scanner with appropriate configurations"""
        self.devices = []
        self.config = {
            "shodan_api_key": "",
            "nvd_api_key": "",
            "scan_timeout": 300,
            "max_devices": 100,
            "output_format": "json",
            "scan_ports": "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                logger.info(f"Configuration loaded from {config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration file: {e}")
        
    def discover_devices(self, target):
        """Discover devices in target network using nmap or basic ping"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}[+] PHASE 1: DEVICE DISCOVERY{Colors.ENDC}")
        logger.info(f"Starting discovery scan on {target}")
        
        print(f"{Colors.YELLOW}Scanning {target}...{Colors.ENDC}")
        
        discovered = []
        
        if not NMAP_AVAILABLE:
            logger.warning("nmap not available, using basic discovery")
            # Fallback to basic ping discovery for single IPs
            if self._is_single_ip(target):
                discovered = self._basic_ping_discovery(target)
            else:
                logger.error("nmap required for network range scanning")
                return []
        else:
            try:
                nm = nmap.PortScanner()
                # Use ping scan for discovery
                scan_result = nm.scan(hosts=target, arguments='-sn -T4')
                
                for host in nm.all_hosts():
                    try:
                        device = DeviceInfo(ip=host)
                        
                        host_info = nm[host]
                        
                        # Get hostname
                        if 'hostnames' in host_info and host_info['hostnames']:
                            device.hostname = host_info['hostnames'][0]['name']
                        
                        # Get MAC address and vendor
                        if 'addresses' in host_info:
                            if 'mac' in host_info['addresses']:
                                device.mac = host_info['addresses']['mac']
                        
                        # Get vendor info
                        if hasattr(nm[host], 'vendor') and device.mac and device.mac in nm[host].vendor():
                            device.vendor = nm[host].vendor()[device.mac]
                        
                        discovered.append(device)
                        logger.debug(f"Device discovered: {host}")
                    except Exception as e:
                        logger.error(f"Error processing host {host}: {e}")
                        
            except Exception as e:
                logger.error(f"Error during nmap discovery: {e}")
                return []
        
        print(f"\n{Colors.GREEN}✓ Discovery completed. Found {len(discovered)} devices{Colors.ENDC}")
        
        # Display discovered devices table
        if discovered:
            self._display_devices_table(discovered)
        
        return discovered
    
    def _is_single_ip(self, target):
        """Check if target is a single IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _basic_ping_discovery(self, target):
        """Basic ping discovery for single IP"""
        discovered = []
        try:
            # Simple socket connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, 80))  # Try port 80
            sock.close()
            
            if result == 0 or self._ping_host(target):
                device = DeviceInfo(ip=target)
                discovered.append(device)
                
        except Exception as e:
            logger.debug(f"Basic discovery error for {target}: {e}")
        
        return discovered
    
    def _ping_host(self, host):
        """Ping a host to check if it's alive"""
        try:
            import subprocess
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '2000', host], 
                                      capture_output=True, text=True)
            else:  # Unix/Linux
                result = subprocess.run(['ping', '-c', '1', '-W', '2', host], 
                                      capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _display_devices_table(self, devices):
        """Display discovered devices in a table format"""
        print(f"\n{Colors.BOLD}Detected devices:{Colors.ENDC}")
        print(f"{'IP':<15} {'MAC':<20} {'Hostname':<30} {'Vendor':<30}")
        print("-" * 95)
        for device in devices:
            print(f"{device.ip:<15} {device.mac or 'N/A':<20} {device.hostname or 'N/A':<30} {device.vendor or 'N/A':<30}")
    
    def scan_device(self, device, index, total):
        """Perform deep scan of a single device to identify services and versions"""
        logger.info(f"Deep scanning device {device.ip}")
        
        print(f"\n{Colors.YELLOW}Deep scanning {device.ip} ({index}/{total}){Colors.ENDC}")
        
        if not NMAP_AVAILABLE:
            logger.warning("nmap not available, skipping service detection")
            return device
        
        try:
            nm = nmap.PortScanner()
            # Service and version detection scan
            scan_result = nm.scan(hosts=device.ip, 
                                arguments=f'-sV -O -T4 -p {self.config["scan_ports"]}')
            
            if device.ip in nm.all_hosts():
                host_data = nm[device.ip]
                
                # Detect operating system
                if 'osmatch' in host_data and host_data['osmatch']:
                    device.os = host_data['osmatch'][0]['name']
                
                # Detect running services
                if 'tcp' in host_data:
                    for port in host_data['tcp']:
                        service_info = host_data['tcp'][port]
                        service_name = service_info.get('name', 'unknown')
                        product = service_info.get('product', '')
                        version = service_info.get('version', '')
                        service_version = f"{product} {version}".strip()
                        
                        device.services[port] = {
                            'protocol': 'tcp',
                            'name': service_name,
                            'version': service_version,
                            'product': product,
                            'extrainfo': service_info.get('extrainfo', ''),
                            'state': service_info.get('state', 'unknown')
                        }
                        
                        if service_version:
                            device.versions[service_name] = service_version
                
                # Display detected services
                if device.services:
                    self._display_services_table(device)
                
                logger.debug(f"Scan completed for {device.ip}, detected {len(device.services)} services")
                
        except Exception as e:
            logger.error(f"Error scanning device {device.ip}: {e}")
        
        return device
    
    def _display_services_table(self, device):
        """Display detected services in a table format"""
        print(f"\n{Colors.BOLD}Services detected on {device.ip}:{Colors.ENDC}")
        print(f"{'Port':<10} {'Protocol':<10} {'Service':<15} {'Version':<40}")
        print("-" * 75)
        for port, service in device.services.items():
            print(f"{port:<10} {service['protocol']:<10} {service['name']:<15} {service['version']:<40}")
    
    def search_vulnerabilities(self, device):
        """Search for known vulnerabilities for identified services on device"""
        if not device.versions:
            return device
            
        print(f"\n{Colors.YELLOW}Searching vulnerabilities for {device.ip}...{Colors.ENDC}")
        logger.info(f"Searching vulnerabilities for device {device.ip}")
        
        # Progress bar for services
        if device.versions:
            progress = ProgressBar(len(device.versions), prefix='Analyzing services:', suffix='')
            
            service_counter = 0
            # Use NVD API to search for vulnerabilities
            for service_name, version in device.versions.items():
                service_counter += 1
                progress.update(service_counter)
                
                query = f"{service_name} {version}"
                try:
                    # Call to NVD API
                    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {
                        "keywordSearch": query, 
                        "resultsPerPage": 10  # Reduced to avoid rate limiting
                    }
                    
                    headers = {"User-Agent": "AdaScan/1.0"}
                    if self.config.get("nvd_api_key"):
                        headers["apiKey"] = self.config["nvd_api_key"]
                    
                    response = requests.get(api_url, params=params, headers=headers, timeout=10)
                    
                    # Handle rate limiting
                    if response.status_code == 429:
                        logger.warning("Rate limited by NVD API, waiting...")
                        time.sleep(2)
                        continue
                    
                    if response.status_code == 200:
                        results = response.json()
                        
                        if "vulnerabilities" in results and results["vulnerabilities"]:
                            for item in results["vulnerabilities"]:
                                cve = item["cve"]
                                vuln_info = {
                                    "id": cve["id"],
                                    "published": cve.get("published", ""),
                                    "lastModified": cve.get("lastModified", ""),
                                    "description": "",
                                    "severity": "N/A",
                                    "cvss_score": 0.0,
                                    "service": service_name,
                                    "version": version
                                }
                                
                                # Extract description
                                if "descriptions" in cve and cve["descriptions"]:
                                    vuln_info["description"] = cve["descriptions"][0]["value"]
                                
                                # Extract CVSS score and severity
                                if "metrics" in cve:
                                    metrics = cve["metrics"]
                                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                                        cvss = metrics["cvssMetricV31"][0]["cvssData"]
                                        vuln_info["cvss_score"] = cvss.get("baseScore", 0.0)
                                        vuln_info["severity"] = cvss.get("baseSeverity", "N/A")
                                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                                        cvss = metrics["cvssMetricV30"][0]["cvssData"]
                                        vuln_info["cvss_score"] = cvss.get("baseScore", 0.0)
                                        vuln_info["severity"] = cvss.get("baseSeverity", "N/A")
                                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                                        cvss = metrics["cvssMetricV2"][0]["cvssData"]
                                        vuln_info["cvss_score"] = cvss.get("baseScore", 0.0)
                                        # Map CVSS v2 to severity levels
                                        score = cvss.get("baseScore", 0.0)
                                        if score >= 9.0:
                                            vuln_info["severity"] = "CRITICAL"
                                        elif score >= 7.0:
                                            vuln_info["severity"] = "HIGH"
                                        elif score >= 4.0:
                                            vuln_info["severity"] = "MEDIUM"
                                        else:
                                            vuln_info["severity"] = "LOW"
                                
                                device.vulnerabilities.append(vuln_info)
                        
                        logger.debug(f"Found {len([v for v in device.vulnerabilities if v['service'] == service_name])} vulnerabilities for {service_name} {version}")
                    
                    # Rate limiting delay
                    time.sleep(0.5)
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"Network error searching vulnerabilities for {service_name} {version}: {e}")
                except Exception as e:
                    logger.error(f"Error searching vulnerabilities for {service_name} {version}: {e}")
        
        # Search for public exploits for identified CVEs
        if device.vulnerabilities and SHODAN_AVAILABLE and self.config.get("shodan_api_key"):
            self.search_exploits(device)
        
        # Display found vulnerabilities
        if device.vulnerabilities:
            self.display_vulnerabilities(device)
        else:
            print(f"\n{Colors.GREEN}✓ No vulnerabilities found for {device.ip}{Colors.ENDC}")
        
        return device
    
    def display_vulnerabilities(self, device):
        """Display found vulnerabilities on screen"""
        if not device.vulnerabilities:
            return
            
        # Sort by severity (CVSS score)
        device.vulnerabilities.sort(key=lambda v: v.get('cvss_score', 0.0), reverse=True)
        
        print(f"\n{Colors.BOLD}Vulnerabilities found for {device.ip}:{Colors.ENDC}")
        print(f"{'CVE ID':<16} {'Service':<15} {'Severity':<10} {'CVSS':<6} {'Description':<60}")
        print("-" * 107)
        
        for vuln in device.vulnerabilities:
            severity = vuln.get('severity', 'N/A')
            severity_color = Colors.severity_color(severity)
            description = vuln.get('description', '')
            if len(description) > 60:
                description = description[:57] + "..."
                
            print(f"{vuln['id']:<16} {vuln['service']:<15} {severity_color}{severity:<10}{Colors.ENDC} {vuln.get('cvss_score', 0.0):<6.1f} {description:<60}")
            
            # Show exploit information if available
            if "exploits" in vuln and vuln["exploits"]:
                print(f"  {Colors.YELLOW}✱ {len(vuln['exploits'])} exploits available{Colors.ENDC}")
    
    def search_exploits(self, device):
        """Search for public exploits for found vulnerabilities"""
        if not self.config.get("shodan_api_key") or not SHODAN_AVAILABLE:
            logger.warning("Shodan API key not configured or shodan module not available, skipping exploit search")
            return device
            
        print(f"\n{Colors.YELLOW}Searching exploits for vulnerabilities...{Colors.ENDC}")
        
        try:
            # Use Shodan Exploit API
            api = shodan.Shodan(self.config["shodan_api_key"])
            
            # Progress bar for CVEs
            if device.vulnerabilities:
                progress = ProgressBar(len(device.vulnerabilities), prefix='Searching exploits:', suffix='')
                
                for i, vuln in enumerate(device.vulnerabilities):
                    progress.update(i+1)
                    
                    try:
                        # Search exploits for CVE ID
                        results = api.exploits.search(vuln["id"])
                        
                        if results.get("total", 0) > 0:
                            vuln["exploits"] = []
                            for exploit in results.get("matches", []):
                                vuln["exploits"].append({
                                    "source": exploit.get("source", "Unknown"),
                                    "description": exploit.get("description", "No description"),
                                    "date": exploit.get("date", "Unknown"),
                                    "url": exploit.get("url", "")
                                })
                            
                            logger.debug(f"Found {len(vuln['exploits'])} exploits for {vuln['id']}")
                        
                        # Rate limiting
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Error searching exploits for {vuln['id']}: {e}")
        except Exception as e:
            logger.error(f"Error using Shodan API: {e}")
        
        return device
    
    def generate_report(self, devices, output_file=None):
        """Generate vulnerability report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"adascan_report_{timestamp}.{self.config['output_format']}"
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}[+] PHASE 3: REPORT GENERATION{Colors.ENDC}")
        print(f"{Colors.YELLOW}Generating report in {self.config['output_format']} format...{Colors.ENDC}")
        
        logger.info(f"Generating report in {self.config['output_format']} format to {output_file}")
        
        try:
            if self.config["output_format"] == "json":
                self._generate_json_report(devices, output_file)
            elif self.config["output_format"] == "csv":
                self._generate_csv_report(devices, output_file)
            elif self.config["output_format"] == "txt":
                self._generate_txt_report(devices, output_file)
            
            print(f"{Colors.GREEN}✓ Report generated successfully: {output_file}{Colors.ENDC}")
            logger.info(f"Report generated successfully: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None
    
    def _generate_json_report(self, devices, output_file):
        """Generate JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "tool": "AdaScan v1.0",
                "total_devices": len(devices)
            },
            "devices": []
        }
        
        for device in devices:
            device_data = {
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "os": device.os,
                "vendor": device.vendor,
                "services": device.services,
                "vulnerabilities": device.vulnerabilities
            }
            report_data["devices"].append(device_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
    
    def _generate_csv_report(self, devices, output_file):
        """Generate CSV report (vulnerabilities)"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Hostname", "OS", "Service", "Version", "CVE ID", "Severity", 
                            "CVSS Score", "Description", "Has Exploits"])
            
            for device in devices:
                for vuln in device.vulnerabilities:
                    has_exploits = "Yes" if vuln.get("exploits") else "No"
                    writer.writerow([
                        device.ip,
                        device.hostname or "",
                        device.os or "",
                        vuln["service"],
                        vuln["version"],
                        vuln["id"],
                        vuln["severity"],
                        vuln["cvss_score"],
                        vuln["description"],
                        has_exploits
                    ])
    
    def _generate_txt_report(self, devices, output_file):
        """Generate text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("AdaScan - VULNERABILITY REPORT\n")
            f.write("="*50 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total scanned devices: {len(devices)}\n\n")
            
            for device in devices:
                f.write(f"Device: {device.ip}\n")
                f.write(f"Hostname: {device.hostname or 'N/A'}\n")
                f.write(f"MAC: {device.mac or 'N/A'}\n")
                f.write(f"OS: {device.os or 'N/A'}\n")
                f.write(f"Vendor: {device.vendor or 'N/A'}\n")
                f.write("\nDetected services:\n")
                f.write("-"*30 + "\n")
                
                for port, service in device.services.items():
                    f.write(f"  - Port {port}/{service['protocol']}: {service['name']} {service['version']}\n")
                
                f.write(f"\nVulnerabilities ({len(device.vulnerabilities)}):\n")
                f.write("-"*30 + "\n")
                for vuln in device.vulnerabilities:
                    f.write(f"  - {vuln['id']} ({vuln['severity']}, CVSS: {vuln['cvss_score']})\n")
                    f.write(f"    Service: {vuln['service']} {vuln['version']}\n")
                    f.write(f"    Description: {vuln['description']}\n")
                    
                    if vuln.get("exploits"):
                        f.write(f"    Available exploits: {len(vuln['exploits'])}\n")
                        for exploit in vuln["exploits"]:
                            f.write(f"      * {exploit['source']}: {exploit['description']}\n")
                            if exploit.get('url'):
                                f.write(f"        URL: {exploit['url']}\n")
                    
                    f.write("\n")
                f.write("\n" + "-"*50 + "\n\n")
    
    def run_scan(self, target, output_file=None):
        """Run complete scan on specified target"""
        # Show banner
        print(BANNER)
        
        print(f"{Colors.BOLD}Initializing scan...{Colors.ENDC}")
        print(f"Target: {Colors.CYAN}{target}{Colors.ENDC}")
        print(f"Date/Time: {Colors.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"Configuration: {Colors.CYAN}{'Custom' if self.config else 'Default'}{Colors.ENDC}")
        
        logger.info(f"Starting complete scan on target: {target}")
        
        # Device discovery
        discovered_devices = self.discover_devices(target)
        
        if not discovered_devices:
            print(f"{Colors.RED}No devices found. Check target specification.{Colors.ENDC}")
            return None
        
        # Limit number of devices to scan
        if len(discovered_devices) > self.config["max_devices"]:
            logger.warning(f"Limiting to {self.config['max_devices']} devices (discovered: {len(discovered_devices)})")
            discovered_devices = discovered_devices[:self.config["max_devices"]]
        
        # Deep scan of each device
        # Deep scan of each device
        print(f"\n{Colors.BOLD}{Colors.CYAN}[+] PHASE 2: DEEP ANALYSIS{Colors.ENDC}")
        scanned_devices = []
        
        for i, device in enumerate(discovered_devices, 1):
            scanned_device = self.scan_device(device, i, len(discovered_devices))
            scanned_devices.append(scanned_device)
        
        # Search for vulnerabilities
        print(f"\n{Colors.BOLD}{Colors.CYAN}[+] VULNERABILITY ASSESSMENT{Colors.ENDC}")
        
        total_vulnerabilities = 0
        for device in scanned_devices:
            device = self.search_vulnerabilities(device)
            total_vulnerabilities += len(device.vulnerabilities)
        
        # Generate summary
        self._display_scan_summary(scanned_devices, total_vulnerabilities)
        
        # Generate report
        report_file = self.generate_report(scanned_devices, output_file)
        
        logger.info(f"Scan completed. Total devices: {len(scanned_devices)}, Total vulnerabilities: {total_vulnerabilities}")
        
        return scanned_devices
    
    def _display_scan_summary(self, devices, total_vulnerabilities):
        """Display scan summary"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.ENDC}")
        print("=" * 50)
        print(f"Total devices scanned: {Colors.CYAN}{len(devices)}{Colors.ENDC}")
        print(f"Total vulnerabilities found: {Colors.CYAN}{total_vulnerabilities}{Colors.ENDC}")
        
        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for device in devices:
            for vuln in device.vulnerabilities:
                severity = vuln.get("severity", "").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        print(f"\nVulnerability breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                color = Colors.severity_color(severity)
                print(f"  {color}{severity}: {count}{Colors.ENDC}")
        
        # Show top vulnerable devices
        vulnerable_devices = [(d, len(d.vulnerabilities)) for d in devices if d.vulnerabilities]
        if vulnerable_devices:
            vulnerable_devices.sort(key=lambda x: x[1], reverse=True)
            print(f"\nTop vulnerable devices:")
            for device, vuln_count in vulnerable_devices[:5]:
                print(f"  {device.ip}: {Colors.RED}{vuln_count} vulnerabilities{Colors.ENDC}")
        
        print("=" * 50)


def create_sample_config():
    """Create a sample configuration file"""
    config = {
        "shodan_api_key": "",
        "nvd_api_key": "",
        "scan_timeout": 300,
        "max_devices": 100,
        "output_format": "json",
        "scan_ports": "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    }
    
    with open("adascan_config.json", "w") as f:
        json.dump(config, f, indent=4)
    
    print(f"{Colors.GREEN}✓ Sample configuration file created: adascan_config.json{Colors.ENDC}")
    print(f"{Colors.YELLOW}Please edit the file to add your API keys.{Colors.ENDC}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="AdaScan - Advanced Network Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 adascan.py 192.168.1.1
  python3 adascan.py 192.168.1.0/24
  python3 adascan.py -t 10.0.0.1-10.0.0.50
  python3 adascan.py -t 192.168.1.1 -o report.json
  python3 adascan.py --create-config
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target IP, IP range, or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)")
    parser.add_argument("-t", "--target", dest="target_alt", help="Target specification (alternative to positional argument)")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-c", "--config", help="Configuration file path", default="adascan_config.json")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("-p", "--ports", help="Port specification (e.g., 22,80,443 or 1-1000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--timeout", type=int, default=300, help="Scan timeout in seconds")
    parser.add_argument("--max-devices", type=int, default=100, help="Maximum number of devices to scan")
    parser.add_argument("--create-config", action="store_true", help="Create sample configuration file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')
    
    # Create sample config and exit
    if args.create_config:
        create_sample_config()
        return
    
    # Determine target
    target = args.target or args.target_alt
    if not target:
        parser.error("Target is required. Use -h for help.")
    
    # Set up logging level
    if args.verbose:
        logging.getLogger("AdaScan").setLevel(logging.DEBUG)
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner(args.config if os.path.exists(args.config) else None)
        
        # Override configuration with command line arguments
        if args.format:
            scanner.config["output_format"] = args.format
        if args.timeout:
            scanner.config["scan_timeout"] = args.timeout
        if args.max_devices:
            scanner.config["max_devices"] = args.max_devices
        if args.ports:
            scanner.config["scan_ports"] = args.ports
        
        # Check dependencies
        missing_deps = []
        if not NMAP_AVAILABLE:
            missing_deps.append("python-nmap")
        if not SHODAN_AVAILABLE:
            missing_deps.append("shodan")
        
        if missing_deps:
            print(f"{Colors.YELLOW}Warning: Optional dependencies missing: {', '.join(missing_deps)}{Colors.ENDC}")
            print(f"{Colors.YELLOW}Install with: pip install {' '.join(missing_deps)}{Colors.ENDC}")
            print(f"{Colors.YELLOW}Some features may be limited.{Colors.ENDC}\n")
        
        # Run scan
        start_time = time.time()
        result = scanner.run_scan(target, args.output)
        end_time = time.time()
        
        if result:
            print(f"\n{Colors.GREEN}✓ Scan completed successfully in {end_time - start_time:.1f} seconds{Colors.ENDC}")
        else:
            print(f"\n{Colors.RED}✗ Scan failed or no results found{Colors.ENDC}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\n{Colors.RED}✗ Error: {e}{Colors.ENDC}")
        sys.exit(1)


if __name__ == "__main__":
    main()