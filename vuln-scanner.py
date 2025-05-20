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
    try:
        with open(CONFIG["banner_file"], "r") as f:
            print(f.read())
    except:
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

# [Rest of the code remains the same as in the previous version...]
# [PortScanner, WebVulnerabilityScanner, SystemScanner, and KasauScanner classes]
# [Only change the main() function to use save_txt_report instead of save_report]

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
    report_file = save_txt_report(results, args.target)
    
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
