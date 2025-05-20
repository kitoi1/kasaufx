#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KASAU VULN SCANNER v2.0
Creator: Kasau
A comprehensive vulnerability scanner with multi-threading, detailed logging, and advanced detection capabilities.
"""

import os
import socket
import requests
import concurrent.futures
import json
import time
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import logging
import sys

# ==============================
# CONFIGURATION
# ==============================
CONFIG = {
    "timeout": 5,
    "threads": 50,
    "user_agent": "KasauScanner/2.0",
    "log_file": "kasau_scan.log",
    "report_file": "kasau_report_{timestamp}.json",
    "banner_file": "banner.txt"
}

# ==============================
# KALI ASCII LOGO
# ==============================
def display_banner():
    """Display the Kali-style ASCII banner"""
    try:
        with open(CONFIG["banner_file"], "r") as f:
            print(f.read())
    except:
        print(r"""
  _  __     _  __         ____    _  __            
 | |/ /__ _| |/ /_ _ ___ / __ \  | |/ /__ _ ___ ___
 | ' </ _` | ' </ _` (_-< (__ |  | ' </ _` (_-</ -_)
 |_|\_\__,_|_|\_\__,_/__/\___/   |_|\_\__,_/__/\___/
                                                   
     -- Kasau's Vuln Scanner v2.0 --
""")

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

def save_report(data: Dict, target: str) -> str:
    """Save scan results to JSON report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = CONFIG["report_file"].format(timestamp=timestamp)
    
    data.update({
        "metadata": {
            "target": target,
            "timestamp": timestamp,
            "version": "2.0",
            "duration": data.get("duration", 0)
        }
    })
    
    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Report saved to {report_file}")
        return report_file
    except IOError as e:
        logger.error(f"Failed to save report: {str(e)}")
        return ""

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
    parser.add_argument("-o", "--output", help="Output file for report")
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
    
    # Run scan
    scanner = KasauScanner(args.target)
    results = scanner.run_scan()
    
    # Save results
    report_file = save_report(results, args.target)
    
    # Print summary
    logger.info("\n[ Scan Summary ]")
    logger.info(f"Target: {args.target}")
    logger.info(f"Open ports: {len(results['port_scan'])}")
    logger.info(f"Web vulnerabilities found: {sum(len(v) for v in results['web_vulns'].values())}")
    logger.info(f"Outdated packages: {len(results['system_checks']['updates']['updates'])}")
    logger.info(f"Scan duration: {results['duration']} seconds")
    logger.info(f"Report saved to: {report_file}")
    logger.info("\n[✓] Scan Complete - Stay Secure! - Kasau")

if __name__ == "__main__":
    main()
