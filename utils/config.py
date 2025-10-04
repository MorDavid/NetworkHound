#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
Configuration constants and default values for the network analyzer
"""

# Default ports to scan
DEFAULT_PORTS = "21,22,23,25,53,80,81,110,119,123,135,137,139,143,264,389,443,445,554,636,1433,1434,3306,3389,5060,5061,5222,5800,5801,5900,5901,5985,5986,8009,8080,8443,9200,44443"

# Default timeouts and thread counts
DEFAULT_SCAN_TIMEOUT = 3
DEFAULT_SCAN_THREADS = 10
DEFAULT_HTTP_TIMEOUT = 5

# Common service mappings
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 119: "NNTP", 123: "NTP",
    135: "RPC", 137: "NetBIOS-NS", 139: "NetBIOS", 143: "IMAP", 264: "BGMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 636: "LDAPS",
    1433: "MSSQL", 1434: "MSSQL-Mon", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5800: "VNC-HTTP", 5801: "VNC-HTTP-Alt",
    5900: "VNC", 5901: "VNC-Alt", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    8009: "AJP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 44443: "HTTPS-Custom"
}

# LDAP search attributes
LDAP_COMPUTER_ATTRIBUTES = ['objectSid', 'cn', 'dNSHostName', 'operatingSystem']
LDAP_SUBNET_ATTRIBUTES = ['cn', 'siteObject', 'description']

# Output limits
MAX_TITLE_LENGTH = 100
MAX_ERROR_LENGTH = 100
MAX_BODY_SIZE = 1048576  # 1MB

# DNS resolution methods
DNS_RESOLUTION_METHODS = [
    'socket',
    'nslookup', 
    'dnspython',
    'getaddrinfo',
    'hostname-fallback'
]
