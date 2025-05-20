#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KASAU VULN SCANNER v2.0
Creator: Kasau
A comprehensive vulnerability scanner with multi-threading, detailed logging, and TXT reporting.
"""

import os
import socket
import requests
import concurrent.futures
import time
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime
import logging
import sys
import textwrap
from typing import List, Dict, Optional, Tuple

# ==============================
# CONFIGURATION
# ==============================
CONFIG = {
    "timeout": 5,
    "threads": 50,
    "user_agent": "KasauScanner/2.0",
    "log_file": "kasau_scan.log",
    "report_file": "kasau_report_{timestamp}.txt",
    "banner_file": "banner.txt",
    "max_report_width": 80
}

# ==============================
# KALI ASCII LOGO
# ==============================
def display_banner():
    """Display the Kali-style ASCII banner"""
    print(textwrap.dedent(r"""
      _  __     _  __         ____    _  __            
     | |/ /__ _| |/ /_ _ ___ / __ \  | |/ /__ _ ___ ___
     | ' </ _` | ' </ _` (_-< (__ |  | ' </ _` (_-</ -_)
     |_|\_\__,_|_|\_\__,_/__/\___/   |_|\_\__,_/__/\___/
                                                      
         -- Kasau's Vuln Scanner v2.0 --
    """))

# ==============================
# LOGGING SETUP
# ==============================
def setup_logging():
    """Configure logging to file and console"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('kasau_scanner')

logger = setup_logging()

# ==============================
# UTILITY FUNCTIONS
# ==============================
def is_valid_target(target: str) -> bool:
    """Validate the target IP or domain"""
    try:
        if not target:
            return False
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        socket.gethostbyname(target)
        return True
    except (socket.gaierror, ValueError):
        return False

def fetch_url_content(url: str, headers: Optional[Dict] = None) -> Optional[requests.Response]:
    """Fetch URL content with error handling"""
    try:
        headers = headers or {"User-Agent": CONFIG["user_agent"]}
        return requests.get(
            url,
            headers=headers,
            timeout=CONFIG["timeout"],
            allow_redirects=True,
            verify=False
        )
    except requests.RequestException as e:
        logger.debug(f"Request failed for {url}: {str(e)}")
        return None

# ==============================
# SCANNING MODULES
# ==============================
class PortScanner:
    """Advanced port scanning with service detection"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB"
    }
    
    @staticmethod
    def scan_port(target: str, port: int) -> Optional[Tuple[int, str]]:
        """Check if a port is open and identify service"""
        try:
            with socket.create_connection((target, port), timeout=CONFIG["timeout"]):
                service = PortScanner.COMMON_PORTS.get(port, "unknown")
                return (port, service)
        except:
            return None
    
    @classmethod
    def scan_ports(cls, target: str) -> List[Dict]:
        """Scan all common ports with multi-threading"""
        logger.info(f"Starting port scan on {target}")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["threads"]) as executor:
            futures = {executor.submit(cls.scan_port, target, port): port for port in cls.COMMON_PORTS}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service = result
                    open_ports.append({"port": port, "service": service})
                    logger.info(f"Found open port: {port} ({service})")
        
        return open_ports

class WebVulnerabilityScanner:
    """Advanced web vulnerability scanner"""
    
    SENSITIVE_PATHS = [
        "/.git/config", "/.env", "/.htaccess", "/web.config",
        "/config.php", "/backup.zip", "/backup.sql",
        "/admin/", "/wp-admin/", "/phpinfo.php",
        "/.well-known/security.txt", "/robots.txt"
    ]
    
    @staticmethod
    def check_sensitive_files(base_url: str) -> List[Dict]:
        """Check for exposed sensitive files"""
        logger.info(f"Checking sensitive files on {base_url}")
        results = []
        
        def check_path(path: str):
            full_url = urljoin(base_url, path)
            response = fetch_url_content(full_url)
            if response and response.status_code == 200:
                size = len(response.text)
                if size > 0:  # Don't count empty responses
                    result = {
                        "url": full_url,
                        "status": response.status_code,
                        "size": size,
                        "type": "sensitive_file"
                    }
                    results.append(result)
                    logger.warning(f"Sensitive file exposed: {full_url}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["threads"]) as executor:
            executor.map(check_path, WebVulnerabilityScanner.SENSITIVE_PATHS)
        
        return results
    
    @staticmethod
    def check_sqli(base_url: str) -> List[Dict]:
        """Check for SQL injection vulnerabilities"""
        logger.info(f"Checking for SQLi on {base_url}")
        test_payloads = [
            ("'", "sql syntax"),
            ("1' OR '1'='1", "sql syntax"),
            ("1 AND 1=1", "mysql"),
            ("1 AND 1=2", "mysql"),
            ("1;SELECT%20*", "sql")
        ]
        
        results = []
        for param in ["id", "user", "product", "page"]:
            for payload, indicator in test_payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = fetch_url_content(test_url)
                if response and indicator.lower() in response.text.lower():
                    result = {
                        "url": test_url,
                        "type": "sqli",
                        "payload": payload,
                        "status": response.status_code
                    }
                    results.append(result)
                    logger.warning(f"Possible SQLi vulnerability: {test_url}")
                    break
        
        return results
    
    @staticmethod
    def check_xss(base_url: str) -> List[Dict]:
        """Check for XSS vulnerabilities"""
        logger.info(f"Checking for XSS on {base_url}")
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        results = []
        for param in ["q", "search", "query", "name"]:
            for payload in test_payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = fetch_url_content(test_url)
                if response and payload.lower() in response.text.lower():
                    result = {
                        "url": test_url,
                        "type": "xss",
                        "payload": payload,
                        "status": response.status_code
                    }
                    results.append(result)
                    logger.warning(f"Possible XSS vulnerability: {test_url}")
                    break
        
        return results
    
    @classmethod
    def scan_web(cls, base_url: str) -> Dict:
        """Run all web vulnerability checks"""
        results = {
            "sensitive_files": cls.check_sensitive_files(base_url),
            "sqli": cls.check_sqli(base_url),
            "xss": cls.check_xss(base_url)
        }
        return results

class SystemScanner:
    """System configuration and patch checker"""
    
    @staticmethod
    def check_updates() -> Dict:
        """Check for available system updates (Linux only)"""
        logger.info("Checking for system updates")
        results = {"updates": []}
        
        if os.name == "posix":
            try:
                output = subprocess.check_output(
                    "apt list --upgradable 2>/dev/null | grep -E 'apache|nginx|mysql|php|wordpress|openssl'",
                    shell=True,
                    universal_newlines=True
                )
                for line in output.splitlines():
                    if line.strip():
                        pkg = line.split('/')[0]
                        results["updates"].append(pkg)
                        logger.warning(f"Outdated package: {pkg}")
            except subprocess.CalledProcessError:
                pass
        
        return results
    
    @staticmethod
    def check_misconfig(base_url: str) -> Dict:
        """Check for common misconfigurations"""
        logger.info(f"Checking for misconfigurations on {base_url}")
        results = {}
        
        # Directory listing
        response = fetch_url_content(base_url)
        if response and "Index of /" in response.text:
            results["directory_listing"] = True
            logger.warning("Directory listing is enabled!")
        
        # HTTP methods
        try:
            response = requests.options(base_url, timeout=CONFIG["timeout"])
            if response.status_code == 200 and "allow" in response.headers:
                methods = response.headers["allow"]
                if "PUT" in methods or "DELETE" in methods:
                    results["dangerous_methods"] = methods
                    logger.warning(f"Dangerous HTTP methods allowed: {methods}")
        except:
            pass
        
        return results

# ==============================
# REPORT GENERATION
# ==============================
def save_txt_report(data: Dict, target: str) -> str:
    """Save scan results to formatted TXT report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = CONFIG["report_file"].format(timestamp=timestamp)
    
    try:
        with open(report_file, 'w') as f:
            # Header
            f.write(f"{'='*CONFIG['max_report_width']}\n")
            f.write(f"KASAU VULNERABILITY SCAN REPORT\n".center(CONFIG['max_report_width']))
            f.write(f"{'='*CONFIG['max_report_width']}\n\n")
            
            # Metadata
            f.write(f"Scan Target: {target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {data.get('duration', 0):.2f} seconds\n\n")
            
            # Port Scan Results
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("OPEN PORTS FOUND:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            for port in data.get('port_scan', []):
                f.write(f"• Port {port['port']} ({port['service']})\n")
            f.write("\n")
            
            # Web Vulnerabilities
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("WEB VULNERABILITIES:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            
            # Sensitive Files
            if data.get('web_vulns', {}).get('sensitive_files'):
                f.write("\nSENSITIVE FILES EXPOSED:\n")
                for file in data['web_vulns']['sensitive_files']:
                    f.write(f"• {file['url']} (Status: {file['status']}, Size: {file['size']} bytes)\n")
            
            # SQLi
            if data.get('web_vulns', {}).get('sqli'):
                f.write("\nSQL INJECTION VULNERABILITIES:\n")
                for vuln in data['web_vulns']['sqli']:
                    f.write(f"• {vuln['url']} (Payload: {vuln['payload']})\n")
            
            # XSS
            if data.get('web_vulns', {}).get('xss'):
                f.write("\nCROSS-SITE SCRIPTING (XSS) VULNERABILITIES:\n")
                for vuln in data['web_vulns']['xss']:
                    f.write(f"• {vuln['url']} (Payload: {vuln['payload']})\n")
            
            if not any(data['web_vulns'].values()):
                f.write("No web vulnerabilities found.\n")
            f.write("\n")
            
            # System Checks
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("SYSTEM CHECKS:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            
            # Outdated Packages
            if data.get('system_checks', {}).get('updates', {}).get('updates'):
                f.write("\nOUTDATED PACKAGES:\n")
                for pkg in data['system_checks']['updates']['updates']:
                    f.write(f"• {pkg}\n")
            else:
                f.write("No outdated packages found.\n")
            
            # Misconfigurations
            if data.get('system_checks', {}).get('misconfig', {}).get('directory_listing'):
                f.write("\nDIRECTORY LISTING ENABLED on root path\n")
            if data.get('system_checks', {}).get('misconfig', {}).get('dangerous_methods'):
                f.write(f"\nDANGEROUS HTTP METHODS ALLOWED: {data['system_checks']['misconfig']['dangerous_methods']}\n")
            
            # Footer
            f.write(f"\n{'='*CONFIG['max_report_width']}\n")
            f.write("SCAN COMPLETE\n".center(CONFIG['max_report_width']))
            f.write(f"{'='*CONFIG['max_report_width']}\n")
            f.write("Generated by Kasau Vulnerability Scanner v2.0\n".center(CONFIG['max_report_width']))
        
        logger.info(f"Report saved to {report_file}")
        return report_file
    except IOError as e:
        logger.error(f"Failed to save report: {str(e)}")
        return ""

# ==============================
# MAIN SCANNER CLASS
# ==============================
class KasauScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "port_scan": [],
            "web_vulns": {},
            "system_checks": {},
            "duration": 0
        }
    
    def run_scan(self) -> Dict:
        """Execute complete vulnerability scan"""
        start_time = time.time()
        
        try:
            # Phase 1: Port Scanning
            self.results["port_scan"] = PortScanner.scan_ports(self.target)
            
            # Phase 2: Web Vulnerability Scanning
            base_url = f"http://{self.target}" if not self.target.startswith(('http://', 'https://')) else self.target
            self.results["web_vulns"] = WebVulnerabilityScanner.scan_web(base_url)
            
            # Phase 3: System Checks
            self.results["system_checks"] = {
                "updates": SystemScanner.check_updates(),
                "misconfig": SystemScanner.check_misconfig(base_url)
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
        
        # Calculate duration
        self.results["duration"] = round(time.time() - start_time, 2)
        self.results["end_time"] = datetime.now().isoformat()
        
        return self.results

# ==============================
# COMMAND LINE INTERFACE
# ==============================
def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Kasau Vulnerability Scanner v2.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Target IP or domain to scan")
    parser.add_argument("-o", "--output", help="Custom output file name for report")
    parser.add_argument("-t", "--threads", type=int, default=CONFIG["threads"],
                       help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    return parser.parse_args()

# ==============================
# MAIN EXECUTION
# ==============================
def main():
    display_banner()
    args = parse_args()
    
    if not is_valid_target(args.target):
        logger.error("Invalid target specified")
        sys.exit(1)
    
    # Update config from CLI args
    if args.threads:
        CONFIG["threads"] = args.threads
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.output:
        CONFIG["report_file"] = args.output
    
    # Run scan
    scanner = KasauScanner(args.target)
    results = scanner.run_scan()
    
    # Save results
    report_file = save_txt_report(results, args.target)
    
    # Print summary
    logger.info("\n[ Scan Summary ]")
    logger.info(f"Target: {args.target}")
    logger.info(f"Open ports: {len(results['port_scan'])}")
    logger.info(f"Web vulnerabilities found: {sum(len(v) for v in results['web_vulns'].values())}")
    
    # Safely handle updates count
    updates = results.get('system_checks', {}).get('updates', {}).get('updates', [])
    logger.info(f"Outdated packages: {len(updates)}")
    
    logger.info(f"Scan duration: {results['duration']} seconds")
    logger.info(f"Report saved to: {report_file}")
    logger.info("\n[✓] Scan Complete - Stay Secure! - Kasau")


if __name__ == "__main__":
    main()
