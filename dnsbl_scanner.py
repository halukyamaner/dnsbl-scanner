"""
Library: DNSBL Scanner
Author: Haluk YAMANER
Email: haluk@halukyamaner.com
Web: https://www.halukyamaner.com
Version: 1.0

Description:
    The DNSBL Scanner is a robust utility designed to assess whether an IP address or domain is listed on any
    DNS-based Blackhole Lists (DNSBLs), which are used to block or flag IPs associated with spam or other
    malicious activities. This tool allows for dynamic modification of the DNSBL provider list, enabling users
    to tailor the scan to their specific security requirements.

Usage:
    Execute the script from the command line by inputting an IP address or domain. It queries each DNSBL provider
    in the list and returns the listing status. The 'dnsbl_providers' list can be customized by users to include
    or exclude specific DNSBLs, offering flexibility in targeting different types of threats.

Requirements:
    Python 3.x
    dns.resolver: Provided by the dnspython package.
    socket: Standard library module for network operations.

Features:
    - Performs checks against a customizable list of DNSBL providers.
    - Outputs the blacklist status for each DNSBL provider queried.
    - Allows users to easily modify the list of DNSBL providers to focus on specific areas of interest or concern.

Warnings:
    - Ensure that input IPs or domains are correctly formatted to avoid errors and ensure reliable scanning results.
    - User modifications to the DNSBL providers list should be done with care, considering the specific formats and
      requirements of DNSBL queries.

DNSBL Providers:
    - Users can edit the 'dnsbl_providers' list according to their needs. Initial providers include:
        - 'zen.spamhaus.org'
        - 'b.barracudacentral.org'
        - 'bl.spamcop.net'
        - plus additional providers as outlined in the script.
"""
import dns.resolver
import socket

# List of well-known DNSBL providers
dnsbl_providers = [
    'zen.spamhaus.org',
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'cbl.abuseat.org',
    'dnsbl.dronebl.org',
    'psbl.surriel.com'
]

def reverse_ip(ip):
    return '.'.join(reversed(ip.split('.')))

def check_blacklist(ip_or_domain):
    results = {}
    try:
        # Resolve domain to IP if necessary
        ip = socket.gethostbyname(ip_or_domain)
    except socket.gaierror:
        print(f"Invalid domain or IP: {ip_or_domain}")
        return results

    reversed_ip = reverse_ip(ip)

    for provider in dnsbl_providers:
        query = f"{reversed_ip}.{provider}"
        try:
            # Query the DNSBL provider
            dns.resolver.resolve(query, 'A')
            results[provider] = 'Listed'
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            results[provider] = 'Not Listed'
        except Exception as e:
            results[provider] = f'Error: {e}'

    return results

if __name__ == "__main__":
    ip_or_domain = input("Enter the domain or IP to check: ")
    blacklist_results = check_blacklist(ip_or_domain)

    for provider, status in blacklist_results.items():
        print(f"{provider}: {status}")
