# DNSBL Scanner

## Overview
DNSBL Scanner is a Python-based utility for checking if an IP address or domain is listed on DNS-based Blackhole Lists (DNSBLs). These lists are commonly used to block or flag IPs associated with spam or other malicious activities.

## Features
- **Customizable DNSBL Providers**: Users can modify the list of DNSBL providers to suit specific security needs.
- **Dynamic Querying**: The tool queries each DNSBL provider and returns the listing status for an input IP address or domain.
- **Flexibility**: Allows for flexibility in targeting different types of threats by modifying the DNSBL providers list.

## Requirements
- Python 3.x
- `dnspython` package for `dns.resolver`
- `socket` for network operations

## Usage
To use DNSBL Scanner, execute the script from the command line with an IP address or domain. The script queries each DNSBL provider in the list and reports back the listing status.

```bash
python dnsbl_scanner.py
