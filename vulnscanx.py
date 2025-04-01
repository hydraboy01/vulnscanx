#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse
import threading
import queue
import re

# টুলের ব্যানার
def show_banner():
    print("""
    ██╗   ██╗██╗   ██╗██╗     ███████╗███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║   ██║██║   ██║██║     ██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║     █████╗  ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ██╔══╝  ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                            Advanced Web Vulnerability Scanner
    """)

# XSS স্ক্যানার
def xss_scan(url, params=None):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert(1)</script>"
    ]
    vulnerabilities = []
    for payload in payloads:
        try:
            if params:
                response = requests.get(url, params={params: payload}, timeout=5)
            else:
                response = requests.post(url, data={params: payload}, timeout=5)
            if payload in response.text:
                vulnerabilities.append(payload)
        except:
            pass
    return vulnerabilities

# SQL ইনজেকশন স্ক্যানার
def sql_injection_scan(url, params=None):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "1' ORDER BY 1--"
    ]
    vulnerabilities = []
    for payload in payloads:
        try:
            if params:
                response = requests.get(url, params={params: payload}, timeout=5)
            else:
                response = requests.post(url, data={params: payload}, timeout=5)
            if "error in your SQL syntax" in response.text.lower() or "warning:" in response.text.lower():
                vulnerabilities.append(payload)
        except:
            pass
    return vulnerabilities

# Broken Link স্ক্যানার
def broken_link_scan(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        broken_links = []
        for link in links:
            absolute_url = urljoin(url, link)
            try:
                res = requests.head(absolute_url, timeout=5, allow_redirects=True)
                if res.status_code >= 400:
                    broken_links.append(absolute_url)
            except:
                broken_links.append(absolute_url)
        return broken_links
    except:
        return []

# Directory Traversal স্ক্যানার
def dir_traversal_scan(url):
    payloads = [
        "../../../../etc/passwd",
        "../index.html",
        "%2e%2e%2fetc%2fpasswd"
    ]
    vulnerabilities = []
    for payload in payloads:
        try:
            test_url = urljoin(url, payload)
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text or "bin/" in response.text:
                vulnerabilities.append(payload)
        except:
            pass
    return vulnerabilities

# মাল্টিথ্রেডেড স্ক্যানার
def scan_worker(q, results, scan_type, url, param=None):
    while not q.empty():
        item = q.get()
        if scan_type == "xss":
            vulns = xss_scan(url, item)
        elif scan_type == "sql":
            vulns = sql_injection_scan(url, item)
        elif scan_type == "dir":
            vulns = dir_traversal_scan(url)
        if vulns:
            results.append((item, vulns))
        q.task_done()

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="VulnScanX - Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-p", "--param", help="Parameter to test (e.g., 'id', 'search')")
    args = parser.parse_args()

    target_url = args.url if args.url.startswith(('http://', 'https://')) else f"http://{args.url}"

    print(f"\n[+] Starting scan on: {target_url}\n")

    # XSS স্ক্যান
    print("[*] Checking for XSS vulnerabilities...")
    xss_vulns = xss_scan(target_url, args.param)
    if xss_vulns:
        print("[!] XSS Vulnerabilities Found:")
        for vuln in xss_vulns:
            print(f" - Payload: {vuln}")
    else:
        print("[✓] No XSS vulnerabilities detected")

    # SQL ইনজেকশন স্ক্যান
    print("\n[*] Checking for SQL Injection vulnerabilities...")
    sql_vulns = sql_injection_scan(target_url, args.param)
    if sql_vulns:
        print("[!] SQL Injection Vulnerabilities Found:")
        for vuln in sql_vulns:
            print(f" - Payload: {vuln}")
    else:
        print("[✓] No SQL Injection vulnerabilities detected")

    # Broken Link স্ক্যান
    print("\n[*] Checking for broken links...")
    broken_links = broken_link_scan(target_url)
    if broken_links:
        print("[!] Broken Links Found:")
        for link in broken_links[:5]:  # শুধু প্রথম ৫টি দেখাবে
            print(f" - {link}")
    else:
        print("[✓] No broken links found")

    # Directory Traversal স্ক্যান
    print("\n[*] Checking for Directory Traversal vulnerabilities...")
    dir_vulns = dir_traversal_scan(target_url)
    if dir_vulns:
        print("[!] Directory Traversal Vulnerabilities Found:")
        for vuln in dir_vulns:
            print(f" - Payload: {vuln}")
    else:
        print("[✓] No Directory Traversal vulnerabilities detected")

    print("\n[+] Scan completed!")

if __name__ == "__main__":
    main()
