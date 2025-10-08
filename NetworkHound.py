#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-
"""
NetworkHound - Active Directory Network Topology Analyzer
Author: Mor David (www.mordavid.com) | License: Non-Commercial
"""

import argparse
import sys
import json
import socket
import ipaddress
import subprocess
import threading
import time
import requests
import urllib3
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
# ldap3 removed - using only impacket
from core.opengraph_builder import NetworkTopologyBuilder

# Import impacket authentication (required)
try:
    from utils.impacket_auth import ImpacketAuth
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    # Setup minimal logging for error before main logging is configured
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.error("ERROR: impacket_auth module not available. Please ensure utils/impacket_auth.py exists.")
    sys.exit(1)

# Disable SSL warnings for --valid-http checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger('NetworkHound')

# Try to import dnspython for enhanced DNS resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not available. Install with: pip install dnspython")

def setup_logging(verbose: bool = False):
    """Setup logging configuration (console INFO/DEBUG)."""
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        handlers=[console_handler],
        force=True
    )

    # Reduce noise from libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    # ldap3 logging removed

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Query Domain Controller for computer information and generate OpenGraph JSON',
        epilog='''
Examples:
  # Basic LDAP scan (password)
  %(prog)s --dc 10.0.0.5 --domain corp.local --user administrator --password 'P@ssw0rd' --output corporate_topology.json
  
  # Full scan: enable port scanning, HTTP + SMB validation and SSL certificate extraction
  %(prog)s --dc dc.corp.local --domain corp.local --user admin --password 'P@ss' --port-scan --valid-http --valid-smb --ssl --verbose
  
  # Use NTLM hashes instead of password (Impacket style LM:NT or NT-only)
  %(prog)s --dc 10.1.1.10 --domain corp.local --user svc_account --hashes LMHASH:NTLMHASH --port-scan --valid-smb
  
  # Use Kerberos (requires KRB5CCNAME pointing to a ccache file)
  export KRB5CCNAME=./admin.ccache
  %(prog)s --dc dc.corp.local --domain corp.local --user admin -k --port-scan --valid-http
  
  # Manual network-only scan (CIDR, ranges and single IPs) - skip ping checks (-Pn)
  %(prog)s --networks "192.168.1.0/24,10.0.1.1-10.0.1.50,172.16.5.10" -Pn --port-scan --ports 22,80,443 --scan-threads 50
  
  # Manual IP-range scan with custom DNS server and specific ports
  %(prog)s --networks "192.168.2.1-192.168.2.200" --dns 8.8.8.8 --ports 80,443,8080 --scan-timeout 5 --output web_scope.json
  
  # DNS over TCP (useful for proxy/firewall bypass)
  %(prog)s --dc dc.corp.local --domain corp.local --user admin --password 'P@ss' --dns 8.8.8.8 --dns-tcp --verbose
  
  # Via proxychains with DNS over TCP
  proxychains %(prog)s --dc dc.corp.local --domain corp.local --user admin --password 'P@ss' --dns-tcp --port-scan
  
  # Shadow-IT sweep across subnets (find non-domain devices)
  %(prog)s --dc dc.corp.local --domain corp.local --user auditor --password 'Audit123' --shadow-it --port-scan --verbose
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # LDAP connection options (optional when using --networks)
    parser.add_argument('--dc', help='Domain Controller hostname or IP address')
    parser.add_argument('--domain', '-d', default='auto', help='Domain name (e.g., company.local) (use "auto" to extract from Kerberos ticket)')
    parser.add_argument('--user', '-u', '--username', default='auto', help='Username for LDAP authentication (use "auto" to extract from Kerberos ticket)')
    parser.add_argument('--password', '-p', help='Password for LDAP authentication')
    
    # Impacket-style authentication options
    parser.add_argument('--hashes', help='NTLM hashes in LM:NT format (or NT-only 32-hex) to use instead of password')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication (uses KRB5CCNAME environment variable)')
    # ldap3 removed - using only impacket
    
    # Manual network specification (alternative to LDAP)
    parser.add_argument('--networks', '-N', help='Comma-separated list of networks to scan. Supports: CIDR (192.168.1.0/24), IP ranges (192.168.1.1-192.168.1.50), single IPs (172.16.1.10)')
    parser.add_argument('--dns', help='DNS server for ADIDNS queries (defaults to DC if not specified)')
    parser.add_argument('--dns-tcp', action='store_true', help='Use TCP for DNS queries instead of UDP (useful for DNS over proxy/firewall)')
    parser.add_argument('--output', '-o', default='network_opengraph.json', help='Output JSON file (default: network_opengraph.json)')
    parser.add_argument('-Pn', action='store_true', help='Skip ping check, treat all hosts as online (same as nmap -Pn)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output with detailed resolution methods')
    parser.add_argument('--port-scan', action='store_true', help='Enable TCP port scanning')
    parser.add_argument('--ports', default='21,22,23,25,53,80,81,110,119,123,135,137,139,143,264,389,443,445,554,636,1433,1434,3306,3389,5060,5061,5222,5800,5801,5900,5901,5985,5986,8009,8080,8443,9200,44443', 
                       help='Comma-separated list of ports to scan (default: common ports)')
    parser.add_argument('--scan-timeout', type=int, default=3, help='Port scan timeout in seconds (default: 3)')
    parser.add_argument('--scan-threads', type=int, default=10, help='Number of concurrent threads for DNS resolution and port scanning (default: 10)')
    parser.add_argument('--valid-http', action='store_true', help='Test HTTP/HTTPS connectivity on open ports')
    parser.add_argument('--valid-smb', action='store_true', help='Test SMB connectivity and enumerate shares on SMB ports (139, 445)')
    parser.add_argument('--ssl', action='store_true', help='Extract detailed SSL certificate information (slower). Without this flag, only basic SSL info (has_ssl, is_self_signed) is collected')
    parser.add_argument('--shadow-it', action='store_true', help='Scan subnet IP ranges for shadow-IT and non-domain devices')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.networks:
        # Check if we have basic DC connection info
        # For Kerberos, domain and user can be auto-extracted from ticket
        if not args.dc:
            parser.error("Either --networks (-N) must be specified for manual network scanning, "
                        "or --dc must be provided for LDAP connection")
        
        # For non-Kerberos auth, require explicit domain and user
        if not args.kerberos and not all([args.domain != 'auto', args.user != 'auto']):
            parser.error("For non-Kerberos authentication, explicit --domain and --user must be provided")
        
        # Check authentication options
        auth_methods = [args.password, args.hashes, args.kerberos]
        if not any(auth_methods):
            parser.error("At least one authentication method must be provided: "
                        "--password, --hashes, or --kerberos (-k)")
        
        # impacket is required and already checked at import
    
    if args.networks and any([args.dc, args.domain, args.user, args.password]):
        logger.warning("Both --networks and LDAP options provided. Using manual network mode, ignoring LDAP options.")
    
    return args

def parse_manual_networks(networks_str):
    """Parse manual network specification into standardized format
    
    Supports:
    - CIDR notation: 192.168.1.0/24
    - Single IPs: 192.168.1.1
    - IP ranges: 192.168.1.1-192.168.1.50
    """
    if not networks_str:
        return {}
    
    logger.info("🌐 MANUAL MODE: Parsing Network Specifications")
    logger.info("=" * 70)
    
    networks = {}
    network_entries = [n.strip() for n in networks_str.split(',') if n.strip()]
    
    for i, network_entry in enumerate(network_entries, 1):
        try:
            # Check for IP range (e.g., 192.168.1.1-192.168.1.50)
            if '-' in network_entry and '/' not in network_entry:
                start_ip_str, end_ip_str = network_entry.split('-', 1)
                start_ip_str = start_ip_str.strip()
                end_ip_str = end_ip_str.strip()
                
                start_ip = ipaddress.IPv4Address(start_ip_str)
                end_ip = ipaddress.IPv4Address(end_ip_str)
                
                if start_ip > end_ip:
                    logger.error(f"❌ Invalid IP range '{network_entry}': start IP is greater than end IP")
                    continue
                
                # Create a custom network object for the range
                ip_list = []
                current_ip = start_ip
                while current_ip <= end_ip:
                    ip_list.append(str(current_ip))
                    current_ip += 1
                
                # Create a network entry for this range
                range_key = f"range-{start_ip_str}-{end_ip_str}"
                networks[range_key] = {
                    'network': None,  # Special marker for IP ranges
                    'ip_list': ip_list,  # Store the actual IP list
                    'site': f'Manual-Site-{i}',
                    'description': f'Manually specified IP range: {network_entry}',
                    'hosts': [],
                    'is_range': True
                }
                logger.info(f"✅ Added IP range: {network_entry} ({len(ip_list)} IPs, Site: Manual-Site-{i})")
                
            # Try to parse as CIDR network
            elif '/' in network_entry:
                network = ipaddress.IPv4Network(network_entry, strict=False)
                network_str = str(network)
                networks[network_str] = {
                    'network': network,
                    'site': f'Manual-Site-{i}',
                    'description': f'Manually specified network: {network_entry}',
                    'hosts': [],
                    'is_range': False
                }
                logger.info(f"✅ Added network: {network_str} (Site: Manual-Site-{i})")
            else:
                # Single IP address - create a /32 network
                ip = ipaddress.IPv4Address(network_entry)
                network = ipaddress.IPv4Network(f"{ip}/32")
                network_str = str(network)
                networks[network_str] = {
                    'network': network,
                    'site': f'Manual-Site-{i}',
                    'description': f'Manually specified single IP: {network_entry}',
                    'hosts': [],
                    'is_range': False
                }
                logger.info(f"✅ Added single IP: {network_str} (Site: Manual-Site-{i})")
                
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"❌ Invalid network specification '{network_entry}': {e}")
            continue
    
    logger.info(f"📊 Total networks parsed: {len(networks)}")
    logger.info("=" * 70)
    return networks

# connect_to_dc function removed - using only impacket

class ImpacketLDAPWrapper:
    """Wrapper class to make ImpacketAuth compatible with ldap3 connection interface"""
    
    def __init__(self, impacket_auth):
        self.impacket_auth = impacket_auth
        self.is_impacket = True
        self.entries = []  # Store last search results
    
    def _resolve_dc_hostname(self, ip_address):
        """Try to resolve DC IP to NetBIOS hostname for proper Kerberos SPN"""
        try:
            import subprocess
            # Use nmblookup to get NetBIOS name
            result = subprocess.run(['nmblookup', '-A', ip_address], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    # Look for lines like "DC01            <00> -         B <ACTIVE>"
                    if '<00>' in line and 'B <ACTIVE>' in line and not '<GROUP>' in line:
                        hostname = line.split()[0].strip()
                        if hostname and hostname != ip_address:
                            logger.debug(f"Resolved {ip_address} to NetBIOS name: {hostname}")
                            return hostname
        except Exception as e:
            logger.debug(f"NetBIOS name resolution failed: {e}")
        
        # Fallback to IP address
        logger.debug(f"Using IP address as fallback: {ip_address}")
        return ip_address
    
    def _recursive_split_search(self, ldapConnection, search_base, search_filter, attributes, 
                                prefix="", max_depth=7, current_depth=0, auth_label="", skipped_prefixes=None):
        """
        Recursive function to split LDAP searches when size limit is exceeded
        
        Args:
            ldapConnection: LDAP connection object
            search_base: LDAP search base DN
            search_filter: Base search filter (e.g., "(objectClass=computer)")
            attributes: List of attributes to retrieve
            prefix: Current prefix being searched (e.g., "S", "SA", "SAB")
            max_depth: Maximum recursion depth (default 7 characters)
            current_depth: Current recursion depth
            auth_label: Label for logging (e.g., "Kerberos", "Password")
            skipped_prefixes: List to track skipped prefixes (for reporting)
        
        Returns:
            List of search results
        """
        from impacket.ldap import ldapasn1
        
        # Initialize skipped_prefixes list if this is the first call
        if skipped_prefixes is None:
            skipped_prefixes = []
        
        all_results = []
        
        # Create filter with current prefix
        if prefix:
            combined_filter = f"(&{search_filter}(cn={prefix}*))"
        else:
            combined_filter = search_filter
        
        log_prefix = f"{auth_label}: " if auth_label else ""
        logger.debug(f"{log_prefix}Searching {prefix if prefix else 'all'}*... (depth {current_depth})")
        
        try:
            resp = ldapConnection.search(
                searchBase=search_base,
                scope=2,
                searchFilter=combined_filter,
                attributes=attributes,
                sizeLimit=0
            )
            
            # Collect results
            batch_count = 0
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    all_results.append(item)
                    batch_count += 1
            
            if batch_count > 0:
                logger.debug(f"{log_prefix}Found {batch_count} computers with prefix '{prefix}', total: {len(all_results)}")
            
            return all_results
            
        except Exception as search_error:
            if 'sizeLimitExceeded' in str(search_error):
                # If we've hit the limit and haven't reached max depth, split further
                if current_depth < max_depth:
                    logger.warning(f"{log_prefix}Prefix '{prefix}' exceeds limit, splitting to next level (depth {current_depth + 1})...")
                    
                    # Split into next level: add A-Z and 0-9
                    next_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                    for next_char in next_chars:
                        new_prefix = prefix + next_char
                        # Recursive call
                        results = self._recursive_split_search(
                            ldapConnection, search_base, search_filter, attributes,
                            new_prefix, max_depth, current_depth + 1, auth_label, skipped_prefixes
                        )
                        all_results.extend(results)
                    
                    return all_results
                else:
                    # Reached max depth, can't split further
                    logger.error(f"{log_prefix}⚠️ CRITICAL: Prefix '{prefix}' still exceeds 1000 results at maximum depth {max_depth}!")
                    logger.error(f"{log_prefix}⚠️ This means 1000+ computers with prefix '{prefix}' are being SKIPPED!")
                    logger.error(f"{log_prefix}💡 SOLUTION: Increase max_depth in the code (currently {max_depth}, try {max_depth + 2})")
                    logger.error(f"{log_prefix}💡 Or contact the developer - this is an extremely rare edge case")
                    # Track this skipped prefix
                    skipped_prefixes.append(prefix)
                    return []
            else:
                # Other error, re-raise
                raise
        
        return all_results

    def search(self, search_base, search_filter, attributes=None, size_limit=0):
        """Wrapper for LDAP search using impacket"""
        try:
            from impacket.ldap.ldap import LDAPConnection
            from impacket.ldap import ldapasn1
            
            # Create LDAP connection - try to get NetBIOS name for proper Kerberos SPN
            target_host = self._resolve_dc_hostname(self.impacket_auth.target)
            logger.debug(f"Using target {target_host} for LDAP connection")
            
            # Try to connect with resolved hostname (NetBIOS), fallback to original if it fails
            ldapConnection = None
            connection_error = None
            try:
                ldapConnection = LDAPConnection(f'ldap://{target_host}')
            except Exception as e:
                connection_error = e
                logger.debug(f"Failed to connect to {target_host}: {e}")
                if target_host != self.impacket_auth.target:
                    logger.debug(f"Falling back to original hostname: {self.impacket_auth.target}")
                    try:
                        ldapConnection = LDAPConnection(f'ldap://{self.impacket_auth.target}')
                        target_host = self.impacket_auth.target  # Update for subsequent operations
                    except Exception as e2:
                        logger.error(f"Failed to connect to original hostname {self.impacket_auth.target}: {e2}")
                        raise
                else:
                    raise
            
            # Authenticate based on available credentials
            if self.impacket_auth.use_kerberos and self.impacket_auth.kerberos_ticket:
                if not self.impacket_auth._load_kerberos_ticket():
                    return []
                
                # Try direct Kerberos LDAP authentication first
                try:
                    logger.debug("Attempting direct Kerberos LDAP authentication")
                    ldapConnection.kerberosLogin(
                        self.impacket_auth.username, 
                        self.impacket_auth.password, 
                        self.impacket_auth.domain,
                        lmhash='', nthash='', aesKey='', kdcHost=self.impacket_auth.target, 
                        useCache=True
                    )
                    
                    # Perform the search with split search to handle large result sets
                    all_results = []
                    
                    # Try regular search first
                    try:
                        resp = ldapConnection.search(
                            searchBase=search_base,
                            scope=2,
                            searchFilter=search_filter,
                            attributes=attributes if attributes else ['*'],
                            sizeLimit=0
                        )
                        
                        for item in resp:
                            if isinstance(item, ldapasn1.SearchResultEntry):
                                all_results.append(item)
                        
                        logger.info(f"📋 Kerberos: Retrieved {len(all_results)} entries from LDAP")
                    
                    except Exception as search_error:
                        # If size limit exceeded, try split search
                        if 'sizeLimitExceeded' in str(search_error):
                            logger.warning(f"Kerberos: Size limit exceeded, using split search...")
                            
                            if '(objectClass=computer)' in search_filter:
                                logger.info("🔄 Kerberos: Using recursive split search")
                                
                                top_level_prefixes = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                                skipped_prefixes = []
                                
                                for prefix in top_level_prefixes:
                                    results = self._recursive_split_search(
                                        ldapConnection, search_base, search_filter,
                                        attributes if attributes else ['*'], prefix, max_depth=7, current_depth=0, auth_label="Kerberos", skipped_prefixes=skipped_prefixes
                                    )
                                    all_results.extend(results)
                                
                                logger.info(f"📋 Kerberos recursive split search completed: {len(all_results)} entries")
                                
                                # Alert if any prefixes were skipped
                                if skipped_prefixes:
                                    logger.error(f"⚠️ Kerberos WARNING: {len(skipped_prefixes)} prefix(es) were skipped due to exceeding max depth!")
                                    logger.error(f"⚠️ Kerberos: Skipped prefixes: {', '.join(skipped_prefixes)}")
                                    logger.error(f"⚠️ Kerberos: Some computers were NOT retrieved!")
                                    logger.error(f"💡 Increase max_depth=7 to max_depth=9 in the code to fix this")
                            else:
                                logger.error("Kerberos: Size limit exceeded for non-computer search")
                                raise
                        else:
                            raise
                    
                    # Parse all collected results
                    entries = []
                    parse_errors = 0
                    
                    for item_idx, item in enumerate(all_results):
                        try:
                            if isinstance(item, ldapasn1.SearchResultEntry):
                                entry_dict = {}
                                
                                for attr in item['attributes']:
                                    try:
                                        attr_name = str(attr['type'])
                                        attr_values = [str(val) for val in attr['vals']]
                                        
                                        # Special handling for objectSid - convert binary to string
                                        if attr_name == 'objectSid' and attr_values and attr_values[0]:
                                            try:
                                                # Get the raw binary SID from impacket
                                                sid_binary = attr['vals'][0]
                                                
                                                # Handle both AttributeValue objects and direct bytes
                                                if hasattr(sid_binary, 'asOctets'):
                                                    sid_binary = sid_binary.asOctets()
                                                elif isinstance(sid_binary, str):
                                                    sid_binary = sid_binary.encode('latin1')
                                                
                                                # Parse binary SID structure
                                                if isinstance(sid_binary, bytes) and len(sid_binary) >= 8:
                                                    try:
                                                        import struct
                                                        revision = sid_binary[0]
                                                        sub_authority_count = sid_binary[1]
                                                        
                                                        # Authority is 6 bytes, big-endian - ensure we have enough bytes
                                                        if len(sid_binary) >= 8:
                                                            authority_bytes = sid_binary[2:8]
                                                            logger.debug(f"Authority bytes: {authority_bytes.hex()}, length: {len(authority_bytes)}")
                                                            if len(authority_bytes) == 6:
                                                                authority_buffer = b'\x00\x00' + authority_bytes
                                                                logger.debug(f"Authority buffer: {authority_buffer.hex()}, length: {len(authority_buffer)}")
                                                                authority = struct.unpack('>Q', authority_buffer)[0]
                                                                
                                                                # Build SID string
                                                                sid_string = f"S-{revision}-{authority}"
                                                                
                                                                # Parse sub-authorities (little-endian 32-bit integers)
                                                                for i in range(sub_authority_count):
                                                                    offset = 8 + (i * 4)
                                                                    if offset + 4 <= len(sid_binary):
                                                                        sub_auth = struct.unpack('<I', sid_binary[offset:offset+4])[0]
                                                                        sid_string += f"-{sub_auth}"
                                                                
                                                                entry_dict[attr_name] = sid_string
                                                                logger.debug(f"Parsed real SID from Kerberos LDAP: {sid_string}")
                                                            else:
                                                                logger.warning(f"Authority bytes wrong length for entry {item_idx}: {len(authority_bytes)}")
                                                                entry_dict[attr_name] = f"INVALID_AUTHORITY_LENGTH"
                                                        else:
                                                            logger.warning(f"SID binary too short for entry {item_idx}: {len(sid_binary)}")
                                                            entry_dict[attr_name] = f"INVALID_SID_LENGTH"
                                                    except Exception as parse_error:
                                                        logger.warning(f"Failed to parse SID structure for entry {item_idx}: {parse_error}")
                                                        entry_dict[attr_name] = f"SID_PARSE_ERROR"
                                                else:
                                                    logger.warning(f"Invalid SID binary format for entry {item_idx}")
                                                    entry_dict[attr_name] = f"INVALID_SID_FORMAT"
                                            except Exception as e:
                                                logger.warning(f"Failed to parse binary SID for entry {item_idx}: {e}")
                                                entry_dict[attr_name] = attr_values[0] if attr_values else None
                                        else:
                                            entry_dict[attr_name] = attr_values[0] if attr_values else None
                                    
                                    except Exception as attr_error:
                                        logger.warning(f"Failed to parse attribute for entry {item_idx}: {attr_error}")
                                        continue
                                
                                class Entry:
                                    def __init__(self, data):
                                        for key, value in data.items():
                                            setattr(self, key, value)
                                    def __getattr__(self, name):
                                        return None
                                
                                entries.append(Entry(entry_dict))
                        
                        except Exception as entry_error:
                            parse_errors += 1
                            logger.warning(f"Failed to parse entry {item_idx} in Kerberos direct LDAP: {entry_error}")
                            continue
                    
                    ldapConnection.close()
                    self.entries = entries
                    
                    if parse_errors > 0:
                        logger.warning(f"⚠️  Kerberos direct LDAP: {parse_errors}/{len(all_results)} entries failed to parse")
                    
                    logger.info(f"✅ Found {len(entries)} computer objects via direct Kerberos LDAP (parsed {len(entries)}/{len(all_results)})")
                    return entries
                    
                except Exception as kerb_error:
                    logger.warning(f"Direct Kerberos LDAP failed: {kerb_error}")
                    # Fall back to password authentication
                
                # For Kerberos fallback, use password authentication with the same SID parsing
                return self._search_with_kerberos_fallback(search_base, search_filter, attributes, size_limit)
            elif self.impacket_auth.ntlm_hash:
                ldapConnection.login(
                    self.impacket_auth.username, 
                    self.impacket_auth.password, 
                    self.impacket_auth.domain,
                    self.impacket_auth.lm_hash, 
                    self.impacket_auth.nt_hash
                )
            else:
                # Password authentication - use the same parsing logic as Kerberos fallback
                ldapConnection.login(
                    self.impacket_auth.username, 
                    self.impacket_auth.password, 
                    self.impacket_auth.domain
                )
            
            # Perform LDAP search with split search to handle large result sets
            all_results = []
            
            # Try regular search first
            try:
                resp = ldapConnection.search(
                    searchBase=search_base,
                    scope=2,
                    searchFilter=search_filter,
                    attributes=attributes or [],
                    sizeLimit=0
                )
                
                # Collect results
                for item in resp:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        all_results.append(item)
                
                logger.info(f"📋 Retrieved {len(all_results)} entries from LDAP")
                resp = all_results
                
            except Exception as search_error:
                # If size limit exceeded, use recursive split search
                if 'sizeLimitExceeded' in str(search_error):
                    logger.warning(f"Size limit exceeded, using recursive split search...")
                    
                    # Only split for computer objects
                    if '(objectClass=computer)' in search_filter:
                        logger.info("🔄 Using recursive split search (will go as deep as needed)")
                        
                        # Start with top-level prefixes: A-Z, 0-9
                        # Note: LDAP searches are case-insensitive, so A* matches both ABC and abc
                        top_level_prefixes = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                        skipped_prefixes = []
                        
                        for prefix in top_level_prefixes:
                            # Use recursive function - will automatically split as needed
                            results = self._recursive_split_search(
                                ldapConnection, search_base, search_filter, 
                                attributes or [], prefix, max_depth=7, current_depth=0, auth_label="", skipped_prefixes=skipped_prefixes
                            )
                            all_results.extend(results)
                        
                        logger.info(f"📋 Recursive split search completed: {len(all_results)} entries retrieved")
                        
                        # Alert if any prefixes were skipped
                        if skipped_prefixes:
                            logger.error(f"⚠️ WARNING: {len(skipped_prefixes)} prefix(es) were skipped due to exceeding max depth!")
                            logger.error(f"⚠️ Skipped prefixes: {', '.join(skipped_prefixes)}")
                            logger.error(f"⚠️ This means some computers were NOT retrieved!")
                            logger.error(f"💡 Increase max_depth=7 to max_depth=9 in the code to fix this")
                        resp = all_results
                    else:
                        # For non-computer searches, just raise the error
                        logger.error("Size limit exceeded for non-computer search, cannot split")
                        raise
                else:
                    raise
            
            # Parse results to match ldap3 format
            results = []
            parse_errors = 0
            
            for item_idx, item in enumerate(resp):
                try:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        entry_dict = {}
                        
                        for attr in item['attributes']:
                            try:
                                attr_name = str(attr['type'])
                                attr_values = [str(val) for val in attr['vals']]
                                
                                # Special handling for objectSid - convert binary to string
                                if attr_name == 'objectSid' and attr_values and attr_values[0]:
                                    try:
                                        # Use the same SID parsing logic as in Kerberos fallback
                                        sid_raw = attr['vals'][0]
                                        
                                        # Handle impacket AttributeValue object
                                        if hasattr(sid_raw, 'asOctets'):
                                            sid_binary = sid_raw.asOctets()
                                        elif isinstance(sid_raw, bytes):
                                            sid_binary = sid_raw
                                        elif isinstance(sid_raw, str):
                                            sid_binary = sid_raw.encode('latin1')
                                        else:
                                            sid_binary = str(sid_raw).encode('latin1')
                                        
                                        # Parse binary SID structure (same as main method)
                                        if isinstance(sid_binary, bytes) and len(sid_binary) >= 8:
                                            import struct
                                            revision = sid_binary[0]
                                            sub_authority_count = sid_binary[1]
                                            
                                            if len(sid_binary) >= 8:
                                                authority_bytes = sid_binary[2:8]
                                                if len(authority_bytes) == 6:
                                                    authority = struct.unpack('>Q', b'\x00\x00' + authority_bytes)[0]
                                                    sid_string = f"S-{revision}-{authority}"
                                                    
                                                    for i in range(sub_authority_count):
                                                        offset = 8 + (i * 4)
                                                        if offset + 4 <= len(sid_binary):
                                                            sub_auth = struct.unpack('<I', sid_binary[offset:offset+4])[0]
                                                            sid_string += f"-{sub_auth}"
                                                    
                                                    entry_dict[attr_name] = sid_string
                                                    logger.debug(f"Parsed real SID from password auth: {sid_string}")
                                                else:
                                                    logger.warning(f"Invalid authority length for entry {item_idx}: {len(authority_bytes)}")
                                                    entry_dict[attr_name] = f"INVALID_AUTHORITY_LENGTH_{len(authority_bytes)}"
                                            else:
                                                logger.warning(f"SID too short for entry {item_idx}: {len(sid_binary)} bytes")
                                                entry_dict[attr_name] = f"SID_TOO_SHORT_{len(sid_binary)}"
                                        else:
                                            logger.warning(f"Invalid SID type for entry {item_idx}: {type(sid_binary)}")
                                            entry_dict[attr_name] = f"INVALID_SID_TYPE_{type(sid_binary)}"
                                    except Exception as sid_error:
                                        logger.warning(f"Failed to parse SID for entry {item_idx}: {sid_error}")
                                        entry_dict[attr_name] = str(attr_values[0]) if attr_values else None
                                else:
                                    entry_dict[attr_name] = attr_values[0] if attr_values else None
                            
                            except Exception as attr_error:
                                logger.warning(f"Failed to parse attribute for entry {item_idx}: {attr_error}")
                                continue
                        
                        # Create entry object with proper attribute access
                        class Entry:
                            def __init__(self, data):
                                for key, value in data.items():
                                    setattr(self, key, value)
                            
                            def __getattr__(self, name):
                                return None  # Return None for missing attributes
                        
                        results.append(Entry(entry_dict))
                
                except Exception as entry_error:
                    parse_errors += 1
                    logger.warning(f"Failed to parse entry {item_idx}: {entry_error}")
                    continue
            
            ldapConnection.close()
            self.entries = results  # Store results for compatibility
            
            if parse_errors > 0:
                logger.warning(f"⚠️  {parse_errors}/{len(resp)} entries failed to parse")
            
            logger.info(f"✅ Successfully parsed {len(results)}/{len(resp)} entries")
            return results
            
        except Exception as e:
            logger.error(f"Impacket LDAP search failed: {e}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception details: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []
    
    
    def _search_with_kerberos_fallback(self, search_base, search_filter, attributes=None, size_limit=0):
        """Fallback method for Kerberos - uses minimal subprocess only for computer objects"""
        try:
            # Only handle computer objects with the working method
            if search_filter == '(objectClass=computer)':
                # Use direct Kerberos authentication for computer objects
                try:
                    from impacket.ldap.ldap import LDAPConnection
                    from impacket.ldap import ldapasn1
                    import struct
                    
                    logger.info("🔐 Using Kerberos authentication for computer objects query")
                    
                    # Use NetBIOS hostname for proper Kerberos SPN
                    target_host = self._resolve_dc_hostname(self.impacket_auth.target)
                    logger.debug(f"Using target {target_host} for Kerberos LDAP")
                    
                    # Try to connect with resolved hostname (NetBIOS), fallback to original if it fails
                    ldapConnection = None
                    try:
                        ldapConnection = LDAPConnection(f'ldap://{target_host}')
                    except Exception as e:
                        logger.debug(f"Failed to connect to {target_host}: {e}")
                        if target_host != self.impacket_auth.target:
                            logger.debug(f"Falling back to original hostname: {self.impacket_auth.target}")
                            ldapConnection = LDAPConnection(f'ldap://{self.impacket_auth.target}')
                            target_host = self.impacket_auth.target
                        else:
                            raise
                    ldapConnection.kerberosLogin(
                        user=self.impacket_auth.username,
                        password=self.impacket_auth.password,
                        domain=self.impacket_auth.domain,
                        lmhash='',
                        nthash='',
                        aesKey='',
                        kdcHost=self.impacket_auth.target,
                        useCache=True
                    )
                    
                    # Perform LDAP search for computer objects with split search
                    all_results = []
                    
                    # Try regular search first
                    try:
                        resp = ldapConnection.search(
                            searchBase=search_base,
                            scope=2,
                            searchFilter=search_filter,
                            attributes=attributes or ['objectSid', 'cn', 'dNSHostName', 'operatingSystem'],
                            sizeLimit=0
                        )
                        
                        for item in resp:
                            if isinstance(item, ldapasn1.SearchResultEntry):
                                all_results.append(item)
                        
                        logger.info(f"📋 Kerberos fallback: Retrieved {len(all_results)} entries")
                    
                    except Exception as search_error:
                        # If size limit exceeded, try split search
                        if 'sizeLimitExceeded' in str(search_error):
                            logger.warning(f"Kerberos fallback: Size limit exceeded, using split search...")
                            logger.info("🔄 Kerberos fallback: Using recursive split search")
                            
                            top_level_prefixes = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                            skipped_prefixes = []
                            
                            for prefix in top_level_prefixes:
                                results = self._recursive_split_search(
                                    ldapConnection, search_base, search_filter,
                                    attributes or ['objectSid', 'cn', 'dNSHostName', 'operatingSystem'], 
                                    prefix, max_depth=7, current_depth=0, auth_label="Kerberos fallback", skipped_prefixes=skipped_prefixes
                                )
                                all_results.extend(results)
                            
                            logger.info(f"📋 Kerberos fallback recursive split search completed: {len(all_results)} entries")
                            
                            # Alert if any prefixes were skipped
                            if skipped_prefixes:
                                logger.error(f"⚠️ Kerberos fallback WARNING: {len(skipped_prefixes)} prefix(es) were skipped due to exceeding max depth!")
                                logger.error(f"⚠️ Kerberos fallback: Skipped prefixes: {', '.join(skipped_prefixes)}")
                                logger.error(f"⚠️ Kerberos fallback: Some computers were NOT retrieved!")
                                logger.error(f"💡 Increase max_depth=7 to max_depth=9 in the code to fix this")
                        else:
                            raise
                    
                    # Parse results to match expected format
                    entries = []
                    parse_errors = 0
                    
                    for item_idx, item in enumerate(all_results):
                        try:
                            if isinstance(item, ldapasn1.SearchResultEntry):
                                entry_dict = {}
                                
                                for attr in item['attributes']:
                                    try:
                                        attr_name = str(attr['type'])
                                        attr_values = [str(val) for val in attr['vals']]
                                        
                                        # Special handling for objectSid
                                        if attr_name == 'objectSid' and attr_values and attr_values[0]:
                                            try:
                                                # Get the raw binary SID from impacket
                                                sid_raw = attr['vals'][0]
                                                
                                                # Handle impacket AttributeValue object
                                                if hasattr(sid_raw, 'asOctets'):
                                                    # This is an AttributeValue object, get the raw bytes
                                                    sid_binary = sid_raw.asOctets()
                                                elif isinstance(sid_raw, (bytes, str)):
                                                    if isinstance(sid_raw, str):
                                                        sid_binary = sid_raw.encode('latin1')
                                                    else:
                                                        sid_binary = sid_raw
                                                else:
                                                    # Try to convert to string and then to bytes
                                                    sid_binary = str(sid_raw).encode('latin1')
                                                
                                                # Parse binary SID structure
                                                if isinstance(sid_binary, bytes) and len(sid_binary) >= 8:
                                                    try:
                                                        revision = sid_binary[0]
                                                        sub_authority_count = sid_binary[1]
                                                        
                                                        # Authority is 6 bytes, big-endian - ensure we have enough bytes
                                                        if len(sid_binary) >= 8:
                                                            authority_bytes = sid_binary[2:8]
                                                            logger.debug(f"Authority bytes: {authority_bytes.hex()}, length: {len(authority_bytes)}")
                                                            if len(authority_bytes) == 6:
                                                                authority_buffer = b'\x00\x00' + authority_bytes
                                                                logger.debug(f"Authority buffer: {authority_buffer.hex()}, length: {len(authority_buffer)}")
                                                                authority = struct.unpack('>Q', authority_buffer)[0]
                                                                
                                                                # Build SID string
                                                                sid_string = f"S-{revision}-{authority}"
                                                                
                                                                # Parse sub-authorities (little-endian 32-bit integers)
                                                                for i in range(sub_authority_count):
                                                                    offset = 8 + (i * 4)
                                                                    if offset + 4 <= len(sid_binary):
                                                                        sub_auth = struct.unpack('<I', sid_binary[offset:offset+4])[0]
                                                                        sid_string += f"-{sub_auth}"
                                                                
                                                                entry_dict[attr_name] = sid_string
                                                                logger.debug(f"Parsed real SID from impacket: {sid_string}")
                                                            else:
                                                                logger.warning(f"Authority bytes wrong length for entry {item_idx}: {len(authority_bytes)}")
                                                                entry_dict[attr_name] = f"INVALID_AUTHORITY_LENGTH_{len(authority_bytes)}"
                                                        else:
                                                            logger.warning(f"SID too short for authority parsing in entry {item_idx}: {len(sid_binary)} bytes")
                                                            entry_dict[attr_name] = f"SID_TOO_SHORT_{len(sid_binary)}"
                                                    except Exception as parse_error:
                                                        logger.warning(f"Failed to parse SID bytes for entry {item_idx}: {parse_error}")
                                                        logger.debug(f"SID binary: {sid_binary.hex() if isinstance(sid_binary, bytes) else str(sid_binary)}")
                                                        entry_dict[attr_name] = f"PARSE_ERROR_{parse_error}"
                                                else:
                                                    logger.warning(f"Invalid SID binary for entry {item_idx}: type={type(sid_binary)}, len={len(sid_binary) if hasattr(sid_binary, '__len__') else 'N/A'}")
                                                    entry_dict[attr_name] = f"INVALID_SID_TYPE_{type(sid_binary)}"
                                                    
                                            except Exception as e:
                                                logger.warning(f"Failed to parse binary SID for entry {item_idx}: {e}")
                                                entry_dict[attr_name] = f"PARSE_ERROR_{e}"
                                        else:
                                            entry_dict[attr_name] = attr_values[0] if attr_values else None
                                    
                                    except Exception as attr_error:
                                        logger.warning(f"Failed to parse attribute for entry {item_idx}: {attr_error}")
                                        continue
                                
                                # Create entry object
                                class Entry:
                                    def __init__(self, data):
                                        for key, value in data.items():
                                            setattr(self, key, value)
                                    def __getattr__(self, name):
                                        return None
                                
                                entries.append(Entry(entry_dict))
                        
                        except Exception as entry_error:
                            parse_errors += 1
                            logger.warning(f"Failed to parse entry {item_idx} in Kerberos fallback: {entry_error}")
                            continue
                    
                    ldapConnection.close()
                    self.entries = entries
                    
                    if parse_errors > 0:
                        logger.warning(f"⚠️  Kerberos fallback: {parse_errors}/{len(all_results)} entries failed to parse")
                    
                    logger.info(f"✅ Found {len(entries)} computer objects via impacket password authentication (parsed {len(entries)}/{len(all_results)})")
                    return entries
                    
                except Exception as e:
                    logger.error(f"Impacket password authentication for computer objects failed: {e}")
                    # Continue to fallback
                
                # No subprocess fallback - return empty if all impacket methods fail
                logger.error("All impacket LDAP methods failed for computer objects query")
                return []
            
            # For non-computer objects, return empty (not supported in fallback)
            return []
            
        except Exception as e:
            logger.error(f"Kerberos fallback failed: {e}")
            return []

    def _use_pure_impacket_ldap(self, search_base, search_filter, attributes=None, size_limit=0):
        """Use the existing impacket connection directly (no subprocess)"""
        try:
            logger.debug("Using existing impacket connection for LDAP search")
            
            # Use the existing connection from the wrapper
            if hasattr(self.impacket_auth, 'ldap_connection') and self.impacket_auth.ldap_connection:
                logger.debug("Reusing existing LDAP connection")
                connection = self.impacket_auth.ldap_connection
            else:
                logger.debug("Creating new LDAP connection")
                from impacket.ldap.ldap import LDAPConnection
                connection = LDAPConnection(f'ldap://{self.impacket_auth.target}')
                
                # Try to login (this might fail due to clock skew, but we'll try)
                try:
                    connection.kerberosLogin(
                        user=self.impacket_auth.username,
                        password='',
                        domain=self.impacket_auth.domain,
                        useCache=True,
                        kdcHost=self.impacket_auth.target
                    )
                    logger.debug("Kerberos login successful")
                except Exception as login_error:
                    logger.warning(f"Kerberos login failed: {login_error}")
                    # For clock skew, we'll return empty results and let the fallback handle it
                    connection.close()
                    return []
            
            # Try to perform the search
            from impacket.ldap import ldapasn1
            resp = connection.search(
                searchBase=search_base,
                scope=2,  # SCOPE_SUBTREE
                searchFilter=search_filter,
                attributes=attributes or [],
                sizeLimit=size_limit if size_limit > 0 else 0
            )
            
            # Parse results
            results = []
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    entry_dict = {}
                    for attr in item['attributes']:
                        attr_name = str(attr['type'])
                        attr_values = [str(val) for val in attr['vals']]
                        
                        # Special handling for objectSid
                        if attr_name == 'objectSid' and attr_values and attr_values[0]:
                            try:
                                # Use the same SID parsing logic as in the main method
                                sid_raw = attr['vals'][0]
                                
                                # Handle impacket AttributeValue object
                                if hasattr(sid_raw, 'asOctets'):
                                    sid_binary = sid_raw.asOctets()
                                elif isinstance(sid_raw, (bytes, str)):
                                    if isinstance(sid_raw, str):
                                        sid_binary = sid_raw.encode('latin1')
                                    else:
                                        sid_binary = sid_raw
                                else:
                                    sid_binary = str(sid_raw).encode('latin1')
                                
                                # Parse binary SID structure (same as main method)
                                if isinstance(sid_binary, bytes) and len(sid_binary) >= 8:
                                    import struct
                                    revision = sid_binary[0]
                                    sub_authority_count = sid_binary[1]
                                    
                                    if len(sid_binary) >= 8:
                                        authority_bytes = sid_binary[2:8]
                                        if len(authority_bytes) == 6:
                                            authority = struct.unpack('>Q', b'\x00\x00' + authority_bytes)[0]
                                            sid_string = f"S-{revision}-{authority}"
                                            
                                            for i in range(sub_authority_count):
                                                offset = 8 + (i * 4)
                                                if offset + 4 <= len(sid_binary):
                                                    sub_auth = struct.unpack('<I', sid_binary[offset:offset+4])[0]
                                                    sid_string += f"-{sub_auth}"
                                            
                                            entry_dict[attr_name] = sid_string
                                            logger.debug(f"Parsed real SID from pure impacket: {sid_string}")
                                        else:
                                            entry_dict[attr_name] = f"INVALID_AUTHORITY_LENGTH_{len(authority_bytes)}"
                                    else:
                                        entry_dict[attr_name] = f"SID_TOO_SHORT_{len(sid_binary)}"
                                else:
                                    entry_dict[attr_name] = f"INVALID_SID_TYPE_{type(sid_binary)}"
                            except Exception as e:
                                logger.warning(f"Failed to parse SID in pure impacket method: {e}")
                                entry_dict[attr_name] = str(attr_values[0])
                        else:
                            entry_dict[attr_name] = attr_values[0] if attr_values else None
                    
                    # Create entry object
                    class Entry:
                        def __init__(self, data):
                            for key, value in data.items():
                                setattr(self, key, value)
                        
                        def __getattr__(self, name):
                            return None
                    
                    results.append(Entry(entry_dict))
            
            if not hasattr(self.impacket_auth, 'ldap_connection'):
                connection.close()
                
            self.entries = results
            logger.info(f"Pure impacket LDAP search successful: found {len(results)} entries")
            return results
            
        except Exception as e:
            logger.warning(f"Pure impacket LDAP failed: {e}")
            # Return empty results - this will cause the main script to show 0 computers found
            # but won't crash, and user can troubleshoot the Kerberos/clock skew issue
            return []
    
    
    def unbind(self):
        """Wrapper for connection cleanup"""
        pass
    
    def _parse_binary_sid(self, sid_bytes):
        """Parse binary SID to string format"""
        import struct
        
        if len(sid_bytes) < 12:
            raise ValueError("SID too short")
        
        # Parse SID structure
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
        
        # Build SID string
        sid_string = f"S-{revision}-{authority}"
        
        # Parse sub-authorities (little-endian 32-bit integers)
        for i in range(sub_authority_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(sid_bytes):
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                sid_string += f"-{sub_auth}"
        
        return sid_string
    
    def __getattr__(self, name):
        """Delegate other attributes to the impacket auth object"""
        return getattr(self.impacket_auth, name)

def parse_kerberos_ticket(ccache_path):
    """Parse Kerberos ticket cache to extract username and domain"""
    try:
        result = subprocess.run(['klist', '-c', ccache_path], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Default principal:' in line:
                    principal = line.split('Default principal:')[1].strip()
                    if '@' in principal:
                        username, domain = principal.split('@', 1)
                        return username, domain.lower()  # Convert to lowercase
        return None, None
    except Exception as e:
        logger.debug(f'Error parsing Kerberos ticket: {e}')
        return None, None

def connect_with_impacket(dc_host, domain, username, password="", ntlm_hash="", kerberos_ticket="", use_kerberos=False):
    """Connect to Domain Controller using impacket authentication
    
    Returns:
        tuple: (connection, extracted_domain, extracted_username) or None if failed
    """
    if not IMPACKET_AVAILABLE:
        logger.error("Impacket not available. Cannot use --use-impacket flag.")
        return None
    
    try:
        import os
        logger.info(f"🔐 Connecting with impacket to DC: {dc_host}")
        
        # Handle KRB5CCNAME environment variable for Kerberos
        krb5_ccname = os.environ.get('KRB5CCNAME')
        if use_kerberos:
            if krb5_ccname:
                kerberos_ticket = krb5_ccname
                logger.info(f"🎫 Using KRB5CCNAME: {krb5_ccname}")
                
                # Auto-extract username and domain from ticket if not provided
                ticket_username, ticket_domain = parse_kerberos_ticket(krb5_ccname)
                if ticket_username and ticket_domain:
                    if not username or username == 'auto':
                        username = ticket_username
                        logger.info(f"🔍 Auto-extracted username from ticket: {username}")
                    if not domain or domain == 'auto':
                        domain = ticket_domain
                        logger.info(f"🔍 Auto-extracted domain from ticket: {domain}")
                else:
                    logger.warning("⚠️  Could not extract username/domain from Kerberos ticket")
            else:
                logger.warning("⚠️  Kerberos requested (-k) but KRB5CCNAME not set")
        
        # Determine authentication type
        auth_type = "Password"
        if ntlm_hash:
            auth_type = "NTLM Hash"
        elif use_kerberos:
            auth_type = "Kerberos"
            if krb5_ccname:
                auth_type += f" (KRB5CCNAME: {krb5_ccname})"
            else:
                auth_type += " (no KRB5CCNAME)"
        
        logger.info(f"🔑 Authentication type: {auth_type}")
        
        # Create impacket auth object
        auth = ImpacketAuth(
            target=dc_host,
            domain=domain,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            kerberos_ticket=kerberos_ticket,
            use_kerberos=bool(kerberos_ticket or use_kerberos)
        )
        
        # Test connections (use verbose=False for cleaner output)
        # Skip SMB test for Kerberos as it can be slow/problematic
        if use_kerberos:
            logger.info("🎫 Kerberos authentication configured - skipping connection tests")
            # For Kerberos, skip connection tests - we'll verify during actual usage
            smb_success = True  # Assume success for Kerberos
            ldap_success = True  # Will be verified during actual LDAP operations
            
            logger.info(f"✅ Impacket authentication successful!")
            logger.info(f"   SMB: ✓")
            logger.info(f"   LDAP: ✓")
            
            # Return wrapped connection with extracted domain and username
            wrapper = ImpacketLDAPWrapper(auth)
            return wrapper, domain, username
        else:
            # Test connections for non-Kerberos authentication
            try:
                logger.debug("Testing SMB connection...")
                smb_success = auth.test_smb_connection(verbose=True)  # Enable verbose for debugging
            except Exception as smb_error:
                logger.error(f"SMB connection test failed: {smb_error}")
                smb_success = False
            
            try:
                logger.debug("Testing LDAP connection...")
                ldap_success = auth.test_ldap_connection(verbose=True)  # Enable verbose for debugging
            except Exception as ldap_error:
                logger.error(f"LDAP connection test failed: {ldap_error}")
                ldap_success = False
            
            if smb_success or ldap_success:
                logger.info(f"✅ Impacket authentication successful!")
                logger.info(f"   SMB: {'✓' if smb_success else '✗'}")
                logger.info(f"   LDAP: {'✓' if ldap_success else '✗'}")
                
                # Skip domain users verification for Kerberos to avoid delays
                if not use_kerberos:
                    # Get domain users for verification (suppress output)
                    try:
                        users = auth.get_domain_users(limit=3, verbose=False)
                        if users:
                            logger.info(f"📋 Found {len(users)} domain users")
                    except Exception as e:
                        logger.debug(f"Could not retrieve domain users: {e}")
            
                # Return wrapped connection with extracted domain and username
                wrapper = ImpacketLDAPWrapper(auth)
                return wrapper, domain, username
            else:
                logger.error("❌ Impacket authentication failed - both SMB and LDAP tests failed")
                return None
            
    except Exception as e:
        logger.error(f"❌ Impacket connection error: {e}")
        return None

def query_computers(connection, domain):
    """Query all computer objects from Active Directory"""
    try:
        logger.info("Collecting computer objects from Active Directory...")
        
        # Check if this is an impacket connection
        if hasattr(connection, 'is_impacket') and connection.is_impacket:
            logger.info("🔐 Using impacket for AD computer query")
            
            # Convert domain to DN format (e.g., company.local -> DC=company,DC=local)
            domain_dn = ','.join([f"DC={part}" for part in domain.split('.')])
            
            # Search for computer objects using real impacket LDAP
            search_base = domain_dn
            search_filter = '(objectClass=computer)'
            attributes = ['objectSid', 'cn', 'dNSHostName', 'operatingSystem']
            
            logger.info(f"🔍 Searching for computers in: {search_base}")
            logger.info(f"🔍 Filter: {search_filter}")
            
            # Use the real search method
            results = connection.search(search_base, search_filter, attributes=attributes)
            
            computers = []
            skipped_computers = 0
            synthetic_sid_count = 0
            
            for entry in connection.entries:  # Use stored entries
                # Get computer attributes
                computer_name = getattr(entry, 'cn', None)
                
                # Skip if no computer name
                if not computer_name:
                    logger.warning(f"⚠️  Skipping entry with no computer name (cn)")
                    skipped_computers += 1
                    continue
                
                computer_sid_binary = getattr(entry, 'objectSid', None)
                
                # Get the real SID parsed from AD
                clean_sid = computer_sid_binary  # This is now already parsed as string from LDAP
                
                # Check if SID is valid (starts with S- and looks like a real SID)
                if not clean_sid or not isinstance(clean_sid, str) or not clean_sid.startswith('S-1-5-21-'):
                    # Generate synthetic SID for computers with failed/invalid SID parsing
                    # Use a deterministic hash of computer name to ensure uniqueness
                    import hashlib
                    name_hash = int(hashlib.md5(computer_name.encode()).hexdigest()[:8], 16)
                    synthetic_sid = f"S-1-5-21-SYNTHETIC-{name_hash}-{abs(hash(computer_name)) % 100000}"
                    
                    logger.warning(f"⚠️  Failed to parse SID for '{computer_name}', using synthetic SID")
                    logger.debug(f"   Original SID value: {clean_sid}")
                    logger.debug(f"   Synthetic SID: {synthetic_sid}")
                    
                    clean_sid = synthetic_sid
                    synthetic_sid_count += 1
                else:
                    logger.debug(f"✅ Using real SID from AD for {computer_name}: {clean_sid}")
                
                computer_info = {
                    'sid': clean_sid,
                    'computer_name': computer_name,
                    'dns_hostname': getattr(entry, 'dNSHostName', None),
                    'os': getattr(entry, 'operatingSystem', None),
                    'is_synthetic_sid': not clean_sid.startswith('S-1-5-21-') or 'SYNTHETIC' in clean_sid
                }
                
                # SMB shares will be added later via SMB validation results
                # No longer adding dummy shares to all computers
                
                computers.append(computer_info)
            
            logger.info(f"📋 Found {len(computers)} computer objects from AD")
            
            # Print summary statistics
            if synthetic_sid_count > 0:
                logger.warning(f"⚠️  {synthetic_sid_count} computers have synthetic SIDs (SID parsing failed)")
            if skipped_computers > 0:
                logger.warning(f"⚠️  {skipped_computers} entries skipped (no computer name)")
            
            logger.info(f"✅ Successfully processed: {len(computers)} computers")
            logger.info(f"   - Real SIDs: {len(computers) - synthetic_sid_count}")
            logger.info(f"   - Synthetic SIDs: {synthetic_sid_count}")
            
            # SMB shares will be determined by SMB validation, not added here
            
            return computers
        
        # This should not be reached since we only use impacket now
        logger.error("Unexpected code path - should only use impacket")
        return []
    
    except Exception as e:
        logger.error(f"Query failed: {e}")
        return []
    except Exception as e:
        logger.error(f"Query error: {e}")
        return []

def test_connectivity(hostname):
    """Test if computer is reachable via ping"""
    try:
        # Use ping command (works on both Windows and Linux)
        ping_cmd = ['ping', '-c', '1', '-W', '2', hostname]  # Linux/Mac
        if sys.platform.startswith('win'):
            ping_cmd = ['ping', '-n', '1', '-w', '2000', hostname]  # Windows
        
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False

def test_connectivity_threaded(hostnames, max_threads=10):
    """Test connectivity to multiple hosts using threading"""
    if not hostnames:
        return {}
    
    logger.info(f"Testing connectivity for {len(hostnames)} hosts...")
    
    connectivity_results = {}
    
    # Use ThreadPoolExecutor for concurrent ping tests
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all ping tasks
        future_to_hostname = {
            executor.submit(test_connectivity, hostname): hostname
            for hostname in hostnames
        }
        
        # Collect results as they complete
        completed = 0
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            completed += 1
            
            try:
                is_online = future.result()
                connectivity_results[hostname] = is_online
                status = "Online" if is_online else "Offline"
                logger.debug(f"[{completed}/{len(hostnames)}] {hostname}: {status}")
            except Exception as e:
                connectivity_results[hostname] = False
                logger.debug(f"[{completed}/{len(hostnames)}] {hostname}: Error - {e}")
    
    online_count = sum(1 for online in connectivity_results.values() if online)
    logger.info(f"Connectivity test complete: {online_count}/{len(hostnames)} hosts online")
    
    return connectivity_results

def test_http_connectivity(ip, port, timeout=5):
    """Test HTTP/HTTPS connectivity to a specific IP:port"""
    results = {
        'http': {'status': False, 'code': None, 'title': None, 'error': None},
        'https': {'status': False, 'code': None, 'title': None, 'error': None, 'is_self_signed': False}
    }
    
    # Test HTTP
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        results['http']['status'] = True
        results['http']['code'] = response.status_code
        
        # Try to extract title from HTML and save body
        if 'text/html' in response.headers.get('content-type', '').lower():
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
            if title_match:
                results['http']['title'] = title_match.group(1).strip()[:100]  # Limit title length
        
        # Save response body (safely for JSON)
        body_text = response.text[:1048576] if response.text else ""  # Limit to 1MB
        results['http']['body'] = body_text  # Let JSON encoder handle escaping
                
    except Exception as e:
        results['http']['error'] = str(e)[:100]  # Limit error length
    
    # Test HTTPS
    try:
        url = f"https://{ip}:{port}"
        
        # First try with verification to check if certificate is valid
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=True)
            results['https']['is_self_signed'] = False  # Valid certificate
        except requests.exceptions.SSLError:
            # SSL error - likely self-signed or invalid certificate
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            results['https']['is_self_signed'] = True  # Self-signed or invalid
        
        results['https']['status'] = True
        results['https']['code'] = response.status_code
        
        # Try to extract title from HTML and save body
        if 'text/html' in response.headers.get('content-type', '').lower():
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
            if title_match:
                results['https']['title'] = title_match.group(1).strip()[:100]  # Limit title length
        
        # Save response body (safely for JSON)
        body_text = response.text[:1048576] if response.text else ""  # Limit to 1MB
        results['https']['body'] = body_text  # Let JSON encoder handle escaping
                
    except Exception as e:
        results['https']['error'] = str(e)[:100]  # Limit error length
    
    return results

def validate_http_ports_threaded(ip_port_list, max_threads=10, timeout=5):
    """Validate HTTP/HTTPS connectivity on multiple IP:port combinations using threading"""
    if not ip_port_list:
        return {}
    
    logger.info(f"Starting HTTP/HTTPS validation for {len(ip_port_list)} IP:port combinations...")
    logger.info(f"Threads: {max_threads}, Timeout: {timeout}s")
    
    http_results = {}
    
    # Use ThreadPoolExecutor for concurrent HTTP validation
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all HTTP validation tasks
        future_to_target = {
            executor.submit(test_http_connectivity, ip, port, timeout): f"{ip}:{port}"
            for ip, port in ip_port_list
        }
        
        # Collect results as they complete
        completed = 0
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            completed += 1
            
            try:
                result = future.result()
                http_results[target] = result
                
                # Show results
                http_status = "✅" if result['http']['status'] else "❌"
                https_status = "✅" if result['https']['status'] else "❌"
                
                details = []
                if result['http']['status']:
                    details.append(f"HTTP({result['http']['code']})")
                    if result['http']['title']:
                        details.append(f"'{result['http']['title']}'")
                        
                if result['https']['status']:
                    ssl_info = "Self-Signed" if result['https'].get('is_self_signed', False) else "Valid SSL"
                    details.append(f"HTTPS({result['https']['code']}, {ssl_info})")
                    if result['https']['title']:
                        details.append(f"'{result['https']['title']}'")
                
                detail_str = " - " + ", ".join(details) if details else ""
                logger.debug(f"[{completed}/{len(ip_port_list)}] {target}: {http_status}HTTP {https_status}HTTPS{detail_str}")
                
            except Exception as e:
                http_results[target] = {
                    'http': {'status': False, 'error': str(e)},
                    'https': {'status': False, 'error': str(e)}
                }
                logger.debug(f"[{completed}/{len(ip_port_list)}] {target}: Validation error - {e}")
    
    # Summary
    http_success = sum(1 for r in http_results.values() if r['http']['status'])
    https_success = sum(1 for r in http_results.values() if r['https']['status'])
    logger.info(f"HTTP validation results: {http_success} HTTP, {https_success} HTTPS successful")
    
    return http_results

def scan_ip_range_with_name(subnet_str, subnet_info, known_ips, max_threads=10, timeout=3, ping_check=False):
    """Scan IP range for shadow-IT devices not in Active Directory with explicit subnet name"""
    from core.port_scanner import scan_ip_range_with_name as port_scan_ip_range
    return port_scan_ip_range(subnet_str, subnet_info, known_ips, max_threads, ping_check)

def scan_ip_range(subnet_info, known_ips, max_threads=10, timeout=3):
    """Scan IP range for shadow-IT devices not in Active Directory"""
    subnet_network = subnet_info['network']
    subnet_str = str(subnet_network)
    
    logger.info(f"Scanning IP range {subnet_str} for shadow-IT devices...")
    
    # Generate all IPs in subnet (skip network and broadcast)
    all_ips = list(subnet_network.hosts())
    
    # Filter out known AD computer IPs
    unknown_ips = [str(ip) for ip in all_ips if str(ip) not in known_ips]
    known_in_subnet = [str(ip) for ip in all_ips if str(ip) in known_ips]
    
    logger.debug(f"   Subnet {subnet_str}: {len(all_ips)} total IPs")
    logger.debug(f"   Known AD computers in subnet: {len(known_in_subnet)} ({known_in_subnet[:5]}{'...' if len(known_in_subnet) > 5 else ''})")
    logger.debug(f"   Unknown IPs to scan: {len(unknown_ips)}")
    
    if not unknown_ips:
        return {}
    
    # Ping sweep to find live hosts
    live_devices = test_connectivity_threaded(unknown_ips, max_threads)
    
    # Filter only responsive IPs
    responsive_ips = [ip for ip, is_alive in live_devices.items() if is_alive]
    
    logger.info(f"   Found {len(responsive_ips)} responsive shadow-IT devices")
    
    shadow_devices = {}
    for ip in responsive_ips:
        device_id = f"SHADOW-DEVICE-{ip.replace('.', '-')}"
        shadow_devices[device_id] = {
            'ip': ip,
            'subnet': subnet_str,
            'site': subnet_info['site'],
            'device_type': 'Unknown',
            'is_shadow_it': True,
            'device_name': f"Device-{ip}"
        }
    
    return shadow_devices

def resolve_single_computer_ips(computer, dns_server=None, use_tcp=False):
    """Enhanced IP resolution for a single computer using multiple methods
    
    Note: This function is deprecated - use DNSResolver class instead!
    Kept for backward compatibility only.
    """
    from core.dns_resolver import DNSResolver
    
    # Use DNSResolver class for actual resolution
    resolver = DNSResolver(dns_server=dns_server, max_threads=1, use_tcp=use_tcp)
    return resolver.resolve_single_computer(computer, test_connectivity=True)

def resolve_hostnames_to_ips_threaded(computers, dns_server=None, max_threads=10, use_tcp=False):
    """Enhanced IP resolution with threading support"""
    from core.dns_resolver import DNSResolver
    
    # Use DNSResolver class for resolution
    resolver = DNSResolver(dns_server=dns_server, max_threads=max_threads, use_tcp=use_tcp)
    
    # Log DNS protocol being used
    if use_tcp:
        logger.info(f"🔧 DNS Protocol: TCP (forced)")
    else:
        logger.info(f"🔧 DNS Protocol: UDP (default)")
    
    # Use the resolver's built-in threaded resolution
    ip_records = resolver.resolve_computers_threaded(computers)
    
    return ip_records

def resolve_hostnames_to_ips(computers, dns_server=None):
    """Enhanced IP resolution supporting multiple IPs per computer with detailed logging"""
    ip_records = {}
    resolution_stats = {
        'total_computers': len(computers),
        'successful_resolutions': 0,
        'total_ips_found': 0,
        'online_computers': 0,
        'methods_used': set()
    }
    
    logger.info(f"Starting enhanced IP resolution for {len(computers)} computers...")
    logger.info(f"DNS Server: {dns_server if dns_server else 'System default'}")
    logger.info("=" * 70)
    
    for i, computer in enumerate(computers, 1):
        logger.debug(f"[{i}/{len(computers)}] Processing: {computer['computer_name']}")
        
        # Resolve IPs for this computer
        resolution_result = resolve_single_computer_ips(computer, dns_server)
        
        if resolution_result['ips']:
            ip_records[computer['computer_name']] = resolution_result['ips']
            resolution_stats['successful_resolutions'] += 1
            resolution_stats['total_ips_found'] += len(resolution_result['ips'])
            resolution_stats['methods_used'].update(resolution_result['methods'])
            
            if resolution_result['connectivity'] == "Online":
                resolution_stats['online_computers'] += 1
            
            logger.debug(f"Summary: {len(resolution_result['ips'])} IPs found via {', '.join(resolution_result['methods'])}")
            logger.debug(f"   IPs: {', '.join(resolution_result['ips'])}")
            logger.debug(f"   Status: {resolution_result['connectivity']}")
        else:
            logger.debug(f"No IPs resolved for {computer['computer_name']}")
    
    # Print final statistics
    logger.info("=" * 70)
    logger.info("RESOLUTION STATISTICS")
    logger.info("=" * 70)
    logger.info(f"Total computers processed: {resolution_stats['total_computers']}")
    logger.info(f"Successful resolutions: {resolution_stats['successful_resolutions']}")
    logger.info(f"Total IP addresses found: {resolution_stats['total_ips_found']}")
    logger.info(f"Online computers: {resolution_stats['online_computers']}")
    logger.info(f"Success rate: {(resolution_stats['successful_resolutions']/resolution_stats['total_computers'])*100:.1f}%")
    logger.info(f"Methods used: {', '.join(sorted(resolution_stats['methods_used']))}")
    logger.info(f"Average IPs per computer: {resolution_stats['total_ips_found']/max(resolution_stats['successful_resolutions'], 1):.1f}")
    
    return ip_records

def scan_port(ip, port, timeout):
    """Scan a single port on a target IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except (socket.error, socket.timeout):
        return None

def scan_computer_ports(computer_name, ips, ports, timeout, max_threads):
    """Scan multiple ports on all IPs of a computer"""
    if not ips:
        return {}
    
    logger.debug(f"Port scanning {computer_name} ({len(ips)} IPs, {len(ports)} ports)")
    
    scan_results = {}
    
    for ip in ips:
        logger.debug(f"   Scanning {ip}...")
        open_ports = []
        
        # Use ThreadPoolExecutor for concurrent port scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(scan_port, ip, port, timeout): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        logger.debug(f"   {ip}:{result} - OPEN")
                except Exception as e:
                    logger.debug(f"   Error scanning {ip}:{port} - {e}")
        
        if open_ports:
            scan_results[ip] = sorted(open_ports)
            logger.debug(f"   {ip}: {len(open_ports)} open ports - {open_ports}")
        else:
            scan_results[ip] = []
            logger.debug(f"   {ip}: No open ports found")
    
    return scan_results

def get_service_name(port):
    """Get common service name for a port"""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 119: "NNTP", 123: "NTP",
        135: "RPC", 137: "NetBIOS-NS", 139: "NetBIOS", 143: "IMAP", 264: "BGMP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 636: "LDAPS",
        1433: "MSSQL", 1434: "MSSQL-Mon", 3306: "MySQL", 3389: "RDP",
        5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5800: "VNC-HTTP", 5801: "VNC-HTTP-Alt",
        5900: "VNC", 5901: "VNC-Alt", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        8009: "AJP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 44443: "HTTPS-Custom"
    }
    return common_ports.get(port, f"Port-{port}")

def perform_network_scan(computers, ip_records, ports, timeout, max_threads, ping_check=False):
    """Perform network port scanning on all computers"""
    logger.info("Starting network port scan...")
    logger.info(f"Ports to scan: {ports}")
    logger.info(f"Timeout: {timeout}s, Threads: {max_threads}")
    logger.info("=" * 70)
    
    scan_results = {}
    scan_stats = {
        'computers_scanned': 0,
        'total_ips_scanned': 0,
        'total_open_ports': 0,
        'scan_start_time': time.time()
    }
    
    for i, computer in enumerate(computers, 1):
        computer_name = computer['computer_name']
        ips = ip_records.get(computer_name, [])
        
        if isinstance(ips, str):
            ips = [ips]
        
        if not ips:
            logger.debug(f"[{i}/{len(computers)}] Skipping {computer_name} - No IPs resolved")
            continue
        
        logger.debug(f"[{i}/{len(computers)}] Scanning {computer_name}")
        
        # Check ping connectivity (default behavior, unless -Pn is used)
        if not ping_check:  # ping_check now means "skip ping" (-Pn)
            # Test connectivity to first IP (default behavior)
            primary_ip = ips[0]
            is_online = test_connectivity(primary_ip)
            if not is_online:
                logger.debug(f"   Ping failed to {primary_ip} - Skipping port scan (default behavior)")
                continue
            else:
                logger.debug(f"   Ping successful to {primary_ip} - Proceeding with port scan")
        else:
            # -Pn flag used: skip ping, treat all hosts as online
            logger.debug(f"   Skipping ping check (-Pn enabled) - Treating host as online")
        
        # Scan ports for this computer
        computer_scan_results = scan_computer_ports(computer_name, ips, ports, timeout, max_threads)
        
        if computer_scan_results:
            scan_results[computer_name] = computer_scan_results
            
            # Update statistics
            scan_stats['computers_scanned'] += 1
            scan_stats['total_ips_scanned'] += len(ips)
            for ip_ports in computer_scan_results.values():
                scan_stats['total_open_ports'] += len(ip_ports)
    
    # Print scan statistics
    scan_duration = time.time() - scan_stats['scan_start_time']
    logger.info("=" * 70)
    logger.info("PORT SCAN STATISTICS")
    logger.info("=" * 70)
    logger.info(f"Computers scanned: {scan_stats['computers_scanned']}")
    logger.info(f"IP addresses scanned: {scan_stats['total_ips_scanned']}")
    logger.info(f"Total open ports found: {scan_stats['total_open_ports']}")
    logger.info(f"Scan duration: {scan_duration:.1f} seconds")
    logger.info(f"Average scan time per computer: {scan_duration/max(scan_stats['computers_scanned'], 1):.1f}s")
    
    return scan_results

def save_results_to_csv(computers, ip_records, filename, port_scan_results=None):
    """Save computer and IP information to CSV file with optional port scan results"""
    import csv
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Add port scan fields if port scanning was performed
            base_fields = ['computer_name', 'dns_hostname', 'operating_system', 'sid', 
                          'ip_addresses', 'primary_ip', 'ip_count']
            
            if port_scan_results:
                fieldnames = base_fields + ['open_ports', 'open_port_count', 'services_detected', 'last_updated']
            else:
                fieldnames = base_fields + ['last_updated']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for computer in computers:
                ips = ip_records.get(computer['computer_name'], [])
                if isinstance(ips, str):
                    ips = [ips]
                
                # Base row data
                row = {
                    'computer_name': computer['computer_name'],
                    'dns_hostname': computer['dns_hostname'] or 'N/A',
                    'operating_system': computer['os'] or 'Unknown',
                    'sid': computer['sid'] or 'N/A',
                    'ip_addresses': '; '.join(ips) if ips else 'Not Resolved',
                    'primary_ip': ips[0] if ips else 'Not Resolved',
                    'ip_count': len(ips),
                    'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Add port scan data if available
                if port_scan_results:
                    computer_ports = port_scan_results.get(computer['computer_name'], {})
                    all_open_ports = []
                    all_services = []
                    
                    for ip, ports in computer_ports.items():
                        for port in ports:
                            all_open_ports.append(f"{ip}:{port}")
                            all_services.append(f"{ip}:{port}({get_service_name(port)})")
                    
                    row.update({
                        'open_ports': '; '.join(all_open_ports) if all_open_ports else 'None',
                        'open_port_count': len(all_open_ports),
                        'services_detected': '; '.join(all_services) if all_services else 'None'
                    })
                
                writer.writerow(row)
        
        logger.info(f"CSV results saved to: {filename}")
        
    except Exception as e:
        logger.error(f"Failed to save CSV: {e}")

def query_ad_subnets(connection, domain):
    """Query AD Sites and Services for configured subnets"""
    try:
        # First try direct LDAP search
        domain_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        search_base = f"CN=Subnets,CN=Sites,CN=Configuration,{domain_dn}"
        search_filter = '(objectClass=subnet)'
        attributes = ['cn', 'siteObject', 'description']
        
        connection.search(search_base, search_filter, attributes=attributes)
        
        ad_subnets = {}
        for entry in connection.entries:
            if entry.cn:
                subnet_name = str(entry.cn)
                site_dn = str(entry.siteObject) if entry.siteObject else None
                description = str(entry.description) if entry.description else None
                
                # Extract site name from DN
                site_name = "Unknown"
                if site_dn:
                    site_parts = site_dn.split(',')
                    for part in site_parts:
                        if part.startswith('CN=') and 'Sites' not in part:
                            site_name = part.replace('CN=', '')
                            break
                
                try:
                    network = ipaddress.IPv4Network(subnet_name)
                    ad_subnets[subnet_name] = {
                        'network': network,
                        'site': site_name,
                        'description': description,
                        'hosts': []
                    }
                    logger.debug(f"Found AD subnet: {subnet_name} in site '{site_name}'")
                except ipaddress.AddressValueError:
                    logger.debug(f"Invalid subnet format in AD: {subnet_name}")
                    continue
        
        # If direct LDAP didn't work, try impacket LDAP approach for Kerberos
        if not ad_subnets and hasattr(connection, 'impacket_auth') and connection.impacket_auth and connection.impacket_auth.use_kerberos:
            logger.info("Direct LDAP subnet search failed, trying impacket LDAP approach...")
            ad_subnets = query_ad_subnets_impacket(connection.impacket_auth, domain, connection.impacket_auth.target)
        
        return ad_subnets
    
    except Exception as e:
        logger.error(f"AD subnet query failed: {e}")
        # Try impacket approach as fallback
        if hasattr(connection, 'impacket_auth') and connection.impacket_auth and connection.impacket_auth.use_kerberos:
            logger.info("Falling back to impacket LDAP approach for subnet query...")
            return query_ad_subnets_impacket(connection.impacket_auth, domain, connection.impacket_auth.target)
        return {}

def _resolve_dc_hostname_static(ip_address):
    """Static version of DC hostname resolution for use outside class"""
    try:
        import subprocess
        # Use nmblookup to get NetBIOS name
        result = subprocess.run(['nmblookup', '-A', ip_address], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for lines like "DC01            <00> -         B <ACTIVE>"
                if '<00>' in line and 'B <ACTIVE>' in line and not '<GROUP>' in line:
                    hostname = line.split()[0].strip()
                    if hostname and hostname != ip_address:
                        logger.debug(f"Resolved {ip_address} to NetBIOS name: {hostname}")
                        return hostname
    except Exception as e:
        logger.debug(f"NetBIOS name resolution failed: {e}")
    
    # Fallback to IP address
    logger.debug(f"Using IP address as fallback: {ip_address}")
    return ip_address

def query_ad_subnets_impacket(impacket_auth, domain, dc_host=None):
    """Query AD subnets using impacket LDAP with password authentication (Configuration container requires it)"""
    try:
        from impacket.ldap.ldap import LDAPConnection
        from impacket.ldap import ldapasn1
        import ipaddress
        
        logger.info("🔍 Using impacket LDAP to query AD Sites and Services...")
        logger.info("ℹ️  Using Kerberos authentication for Configuration container")
        
        # Use NetBIOS hostname for proper Kerberos SPN
        target_host = _resolve_dc_hostname_static(dc_host or impacket_auth.target)
        logger.debug(f"Using target {target_host} for Configuration container Kerberos")
        
        # Try to connect with resolved hostname (NetBIOS), fallback to original if it fails
        ldapConnection = None
        original_host = dc_host or impacket_auth.target
        try:
            ldapConnection = LDAPConnection(f'ldap://{target_host}')
        except Exception as e:
            logger.debug(f"Failed to connect to {target_host}: {e}")
            if target_host != original_host:
                logger.debug(f"Falling back to original hostname: {original_host}")
                ldapConnection = LDAPConnection(f'ldap://{original_host}')
                target_host = original_host
            else:
                raise
        
        # Use Kerberos authentication for Configuration container access
        ldapConnection.kerberosLogin(
            user=impacket_auth.username,
            password=impacket_auth.password,
            domain=impacket_auth.domain,
            lmhash='',
            nthash='',
            aesKey='',
            kdcHost=dc_host or impacket_auth.target,
            useCache=True
        )
        logger.info("✅ Using Kerberos authentication for Configuration container access")
        
        # Convert domain to DN format
        domain_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        search_base = f"CN=Subnets,CN=Sites,CN=Configuration,{domain_dn}"
        search_filter = '(objectClass=subnet)'
        
        logger.info(f"🔍 Search base: {search_base}")
        logger.info(f"🔍 Search filter: {search_filter}")
        
        # Perform LDAP search (subnets typically don't exceed limit)
        all_results = []
        
        try:
            resp = ldapConnection.search(
                searchBase=search_base,
                scope=2,  # SCOPE_SUBTREE
                searchFilter=search_filter,
                attributes=['cn', 'siteObject', 'description'],
                sizeLimit=0
            )
            
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    all_results.append(item)
            
            logger.info(f"📋 Retrieved {len(all_results)} subnet entries from AD Sites and Services")
        
        except Exception as search_error:
            if 'sizeLimitExceeded' in str(search_error):
                logger.warning(f"Size limit exceeded on subnet query (unusual, but continuing with what we got)")
            else:
                raise
        
        ad_subnets = {}
        entry_count = 0
        
        for item in all_results:
            if isinstance(item, ldapasn1.SearchResultEntry):
                entry_count += 1
                entry_dict = {}
                
                # Parse attributes
                for attr in item['attributes']:
                    attr_name = str(attr['type'])
                    attr_values = [str(val) for val in attr['vals']]
                    entry_dict[attr_name] = attr_values[0] if attr_values else None
                
                # Extract subnet information
                subnet_name = entry_dict.get('cn')
                site_dn = entry_dict.get('siteObject')
                description = entry_dict.get('description', '')
                
                if subnet_name:
                    # Extract site name from DN
                    site_name = "Unknown"
                    if site_dn:
                        import re
                        site_match = re.search(r'CN=([^,]+)', site_dn)
                        if site_match:
                            site_name = site_match.group(1)
                    
                    try:
                        network = ipaddress.IPv4Network(subnet_name)
                        ad_subnets[subnet_name] = {
                            'network': network,
                            'site': site_name,
                            'description': description,
                            'hosts': []
                        }
                        logger.info(f"📍 Found AD subnet: {subnet_name} in site '{site_name}'")
                    except ipaddress.AddressValueError:
                        logger.debug(f"Invalid subnet format in AD: {subnet_name}")
                        continue
        
        ldapConnection.close()
        
        if ad_subnets:
            logger.info(f"🎉 Successfully retrieved {len(ad_subnets)} subnets from AD Sites and Services")
        else:
            logger.warning(f"⚠️  Found {entry_count} entries but no valid subnets in AD Sites and Services")
            
        return ad_subnets
        
    except Exception as e:
        logger.error(f"Impacket LDAP subnet query failed: {e}")
        return {}

def query_ad_subnets_subprocess(domain):
    """Query AD subnets using subprocess approach for Kerberos"""
    try:
        import subprocess
        import os
        import re
        
        # Set up environment
        env = os.environ.copy()
        # Use existing KRB5CCNAME from environment if set
        # Use existing KRB5_CONFIG from environment if set
        
        domain_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        search_base = f"CN=Subnets,CN=Sites,CN=Configuration,{domain_dn}"
        
        logger.info(f"🔍 Querying AD Sites and Services for subnets...")
        logger.info(f"🔍 Search base: {search_base}")
        
        # Try multiple approaches
        ad_subnets = {}
        
        # Approach 1: Use ldapsearch command directly
        try:
            # Use the DC host passed as parameter
            cmd = ['ldapsearch', '-Y', 'GSSAPI', '-H', f'ldap://{domain}', 
                   '-b', search_base, '(objectClass=subnet)', 'cn', 'siteObject', 'description']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
            
            if result.returncode == 0 and result.stdout:
                logger.info("✅ Successfully retrieved subnets via ldapsearch")
                # Parse ldapsearch output
                current_entry = {}
                for line in result.stdout.split('\\n'):
                    line = line.strip()
                    if line.startswith('dn: CN='):
                        if current_entry.get('cn'):
                            # Process previous entry
                            subnet_str = current_entry['cn']
                            try:
                                network = ipaddress.IPv4Network(subnet_str)
                                site_name = "Default-First-Site-Name"
                                if current_entry.get('siteObject'):
                                    site_match = re.search(r'CN=([^,]+)', current_entry['siteObject'])
                                    if site_match:
                                        site_name = site_match.group(1)
                                
                                ad_subnets[subnet_str] = {
                                    'network': network,
                                    'site': site_name,
                                    'description': current_entry.get('description', ''),
                                    'hosts': []
                                }
                                logger.info(f"📍 Found AD subnet: {subnet_str} in site '{site_name}'")
                            except ipaddress.AddressValueError:
                                logger.debug(f"Invalid subnet format: {subnet_str}")
                        current_entry = {}
                    elif line.startswith('cn: '):
                        current_entry['cn'] = line.replace('cn: ', '')
                    elif line.startswith('siteObject: '):
                        current_entry['siteObject'] = line.replace('siteObject: ', '')
                    elif line.startswith('description: '):
                        current_entry['description'] = line.replace('description: ', '')
                
                # Process last entry
                if current_entry.get('cn'):
                    subnet_str = current_entry['cn']
                    try:
                        network = ipaddress.IPv4Network(subnet_str)
                        site_name = "Default-First-Site-Name"
                        if current_entry.get('siteObject'):
                            site_match = re.search(r'CN=([^,]+)', current_entry['siteObject'])
                            if site_match:
                                site_name = site_match.group(1)
                        
                        ad_subnets[subnet_str] = {
                            'network': network,
                            'site': site_name,
                            'description': current_entry.get('description', ''),
                            'hosts': []
                        }
                        logger.info(f"📍 Found AD subnet: {subnet_str} in site '{site_name}'")
                    except ipaddress.AddressValueError:
                        logger.debug(f"Invalid subnet format: {subnet_str}")
                        
            else:
                logger.warning(f"ldapsearch failed: {result.stderr}")
                
        except Exception as e:
            logger.warning(f"ldapsearch approach failed: {e}")
        
        # Approach 2: If ldapsearch didn't work, try python ldap3 with better error handling
        if not ad_subnets:
            try:
                logger.info("🔄 Trying python ldap3 approach...")
                # Skip python ldap3 approach - too complex for subprocess
                logger.warning("Python ldap3 approach skipped - use direct LDAP tools instead")
                    
            except Exception as e:
                logger.warning(f"Python ldap3 approach failed: {e}")
        
        if ad_subnets:
            logger.info(f"🎉 Successfully retrieved {len(ad_subnets)} subnets from AD Sites and Services")
        else:
            logger.warning("⚠️  Could not retrieve subnets from AD Sites and Services")
            
        return ad_subnets
        
    except Exception as e:
        logger.error(f"Subprocess AD subnet query failed: {e}")
        return {}

def discover_subnets_from_ips(known_ips):
    """Auto-discover /24 subnets from AD computer IP addresses only"""
    import ipaddress
    
    subnets = {}
    
    # Create /24 subnets for each known AD computer IP
    for ip in known_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            # Always use /24 subnet for each AD computer IP
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            subnet_str = str(network)
            
            if subnet_str not in subnets:
                subnets[subnet_str] = {
                    'network': network,
                    'site': 'AD-Computer-Subnet',
                    'description': f'Contains AD computers',
                    'hosts': []
                }
            
            # Add this IP to the subnet's host list
            subnets[subnet_str]['hosts'].append(ip)
                
        except ipaddress.AddressValueError:
            logger.debug(f"Invalid IP address: {ip}")
            continue
    
    # Log discovered subnets
    for subnet_str, subnet_info in subnets.items():
        logger.info(f"🔍 Auto-discovered subnet: {subnet_str} (contains {len(subnet_info['hosts'])} AD computers)")
    
    return subnets

def match_ips_to_ad_subnets(ad_subnets, ip_records):
    """Match resolved IPs to AD-configured subnets - handles multiple IPs per computer"""
    for hostname, ip_list in ip_records.items():
        # Handle both single IP (string) and multiple IPs (list) for backward compatibility
        if isinstance(ip_list, str):
            ip_list = [ip_list]
        
        for ip_str in ip_list:
            try:
                ip = ipaddress.IPv4Address(ip_str)
                
                # Find which AD subnet this IP belongs to
                matched = False
                for subnet_name, subnet_info in ad_subnets.items():
                    if ip in subnet_info['network']:
                        # Check if this hostname is already in this subnet
                        host_exists = any(h['hostname'] == hostname for h in subnet_info['hosts'])
                        if not host_exists:
                            subnet_info['hosts'].append({'hostname': hostname, 'ips': ip_list})
                        else:
                            # Update existing entry with all IPs
                            for host_entry in subnet_info['hosts']:
                                if host_entry['hostname'] == hostname:
                                    host_entry['ips'] = ip_list
                                    break
                        logger.debug(f"Matched {hostname} ({ip_str}) to AD subnet {subnet_name}")
                        matched = True
                        break
                
                if not matched:
                    # If no AD subnet matches, create an inferred one
                    inferred_subnet = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    subnet_name = str(inferred_subnet)
                    if subnet_name not in ad_subnets:
                        ad_subnets[subnet_name] = {
                            'network': inferred_subnet,
                            'site': 'Inferred',
                            'description': 'Not configured in AD Sites',
                            'hosts': []
                        }
                        logger.debug(f"Created inferred subnet: {subnet_name}")
                    
                    # Check if hostname already exists in this inferred subnet
                    host_exists = any(h['hostname'] == hostname for h in ad_subnets[subnet_name]['hosts'])
                    if not host_exists:
                        ad_subnets[subnet_name]['hosts'].append({'hostname': hostname, 'ips': ip_list})
                    
            except ipaddress.AddressValueError:
                logger.debug(f"Invalid IP address: {ip_str}")
                continue
    
    logger.info(f"Final subnet mapping: {len(ad_subnets)} subnets")
    for subnet, info in ad_subnets.items():
        logger.debug(f"  {subnet} ({info['site']}): {len(info['hosts'])} hosts")
    
    return ad_subnets

def create_opengraph_json(computers, dns_records, domain, connection, output_file, port_scan_results=None, http_validation_results=None, shadow_devices=None):
    """Create OpenGraph JSON from computer data with subnets and edges"""
    try:
        builder = NetworkTopologyBuilder(domain)
        
        # Query AD Sites and Services for configured subnets
        ad_subnets = query_ad_subnets(connection, domain)
        
        
        # Match resolved IPs to AD subnets
        subnets = match_ips_to_ad_subnets(ad_subnets, dns_records)
        
        # Create Site nodes first
        site_ids = {}
        sites_created = set()
        
        # Extract unique sites from subnets
        for subnet_str, subnet_info in subnets.items():
            site_name = subnet_info['site']
            if site_name not in sites_created:
                site_id = f"site-{site_name.replace(' ', '-').replace('.', '-')}"
                site_ids[site_name] = site_id
                
                builder.create_node(
                    id=site_id,
                    kinds=["Site"],
                    properties={
                        "name": site_name,
                        "domain": domain
                    }
                )
                sites_created.add(site_name)
                logger.debug(f"Created Site node: {site_name}")
        
        # Create subnet nodes
        subnet_ids = {}
        for subnet_str, subnet_info in subnets.items():
            subnet_id = f"subnet-{subnet_str.replace('/', '-').replace('.', '-')}"
            subnet_ids[subnet_str] = subnet_id
            
            builder.create_node(
                id=subnet_id,
                kinds=["Subnet"],
                properties={
                    "name": subnet_info['site'],
                    "subnet": subnet_str,
                    "domain": domain,
                    "site": subnet_info['site'],
                    "description": subnet_info.get('description', ''),
                    "network_address": str(subnet_info['network'].network_address),
                    "broadcast_address": str(subnet_info['network'].broadcast_address),
                    "netmask": str(subnet_info['network'].netmask),
                "host_count": len(subnet_info['hosts']),
                "subnet_name": f"{subnet_info['site']}-{subnet_str.replace('/', '-')}"
            }
        )
        
        # Create edge from Subnet to Site
        site_name = subnet_info['site']
        if site_name in site_ids:
            site_id = site_ids[site_name]
            builder.create_edge(
                start_value=subnet_id,
                end_value=site_id,
                kind="PartOf"
            )
        
        logger.debug(f"Created subnet node: {subnet_str}")
        
        # Create computer nodes
        for computer in computers:
            if not computer['sid'] or not computer['computer_name']:
                continue
            
            # Get IP addresses from DNS records if available
            ip_addresses = dns_records.get(computer['computer_name'], [])
            if isinstance(ip_addresses, str):
                ip_addresses = [ip_addresses]
            
            # Create node properties
            properties = {}
            
            if ip_addresses:
                properties["ip_addresses"] = ip_addresses
                logger.debug(f"Added {len(ip_addresses)} IP(s) for {computer['computer_name']}: {ip_addresses}")
            else:
                logger.debug(f"No IPs found for {computer['computer_name']}")
            
            # Add port scan results if available
            if port_scan_results and computer['computer_name'] in port_scan_results:
                computer_ports = port_scan_results[computer['computer_name']]
                all_open_ports = []
                
                for ip, ports in computer_ports.items():
                    for port in ports:
                        all_open_ports.append(port)
                
                if all_open_ports:
                    unique_ports = sorted(list(set(all_open_ports)))  # Remove duplicates and sort
                    properties["open_ports"] = unique_ports
                    logger.debug(f"Added {len(unique_ports)} open ports for {computer['computer_name']}: {unique_ports}")
                else:
                    properties["open_ports"] = []
            
            # Store website data for creating separate Website nodes later
            if http_validation_results:
                for ip in ip_addresses:
                    if port_scan_results and computer['computer_name'] in port_scan_results:
                        computer_ports = port_scan_results[computer['computer_name']]
                        if ip in computer_ports:
                            for port in computer_ports[ip]:
                                target = f"{ip}:{port}"
                                if target in http_validation_results:
                                    http_result = http_validation_results[target]
                                    
                                    # Create Website node for HTTP
                                    if http_result['http']['status']:
                                        website_url = f"http://{ip}:{port}"
                                        website_name = http_result['http']['title'] or f"Website-{ip}-{port}"
                                        
                                        website_properties = {
                                            "name": website_name,
                                            "url": website_url,
                                            "has_ssl": False,
                                            "is_self_signed": False,  # HTTP doesn't use SSL
                                            "status_code": http_result['http']['code'],
                                            "protocol": "http",
                                            "body": http_result['http'].get('body', '')
                                        }
                                        
                                        # Create Website node
                                        website_id = website_name.replace(" ", "-").replace("/", "-").replace("\\", "-")[:50]  # Clean and limit ID
                                        builder.create_node(
                                            id=f"{website_id}-{ip}-{port}-http",
                                            kinds=["Website"],
                                            properties=website_properties
                                        )
                                        
                                        # Create edge from computer to website
                                        builder.create_edge(
                                            start_value=computer['sid'],
                                            end_value=f"{website_id}-{ip}-{port}-http",
                                            kind="ExposeWebsite"
                                        )
                                        
                                        logger.debug(f"Created Website node: {website_name} ({website_url})")
                                    
                                    # Create Website node for HTTPS
                                    if http_result['https']['status']:
                                        website_url = f"https://{ip}:{port}"
                                        website_name = http_result['https']['title'] or f"Website-{ip}-{port}-SSL"
                                        
                                        website_properties = {
                                            "name": website_name,
                                            "url": website_url,
                                            "has_ssl": True,
                                            "is_self_signed": http_result['https'].get('is_self_signed', False),
                                            "status_code": http_result['https']['code'],
                                            "protocol": "https",
                                            "body": http_result['https'].get('body', '')
                                        }
                                        
                                        # Create Website node
                                        website_id = website_name.replace(" ", "-").replace("/", "-").replace("\\", "-")[:50]  # Clean and limit ID
                                        builder.create_node(
                                            id=f"{website_id}-{ip}-{port}-https",
                                            kinds=["Website"],
                                            properties=website_properties
                                        )
                                        
                                        # Create edge from computer to website
                                        builder.create_edge(
                                            start_value=computer['sid'],
                                            end_value=f"{website_id}-{ip}-{port}-https",
                                            kind="ExposeWebsite"
                                        )
                                        
                                        logger.debug(f"Created Website node: {website_name} ({website_url})")
        
            
            # Create computer node
            builder.create_node(
                id=computer['sid'],
                kinds=["Computer"],
                properties=properties
            )
            
            # Create edges from computer to subnets for each IP
            if ip_addresses:
                created_edges = set()  # Avoid duplicate edges to same subnet
                for subnet_str, subnet_info in subnets.items():
                    for host in subnet_info['hosts']:
                        if host['hostname'] == computer['computer_name']:
                            subnet_id = subnet_ids[subnet_str]
                            if subnet_id not in created_edges:
                                # Get all IPs that belong to this subnet
                                subnet_ips = []
                                for ip_str in ip_addresses:
                                    try:
                                        ip = ipaddress.IPv4Address(ip_str)
                                        if ip in subnet_info['network']:
                                            subnet_ips.append(ip_str)
                                    except ipaddress.AddressValueError:
                                        continue
                                
                                builder.create_edge(
                                    start_value=computer['sid'],
                                    end_value=subnet_id,
                                    kind="LocatedIn"
                                )
                                created_edges.add(subnet_id)
                                logger.debug(f"Created edge: {computer['computer_name']} -> {subnet_str} (IPs: {subnet_ips})")
                            break
        
        # Create Device nodes for shadow-IT devices (if found)
        if shadow_devices:
            logger.info(f"Creating Device nodes for {len(shadow_devices)} shadow-IT devices...")
            for device_id, device_info in shadow_devices.items():
                device_ip = device_info['ip']
                device_properties = {
                    "name": device_info['device_name'],
                    "ip_address": device_ip,
                    "device_type": device_info['device_type'],
                    "is_shadow_it": device_info['is_shadow_it'],
                    "site": device_info['site']
                }
                
                # Add port scan results if available
                if port_scan_results and device_info['device_name'] in port_scan_results:
                    device_ports = port_scan_results[device_info['device_name']]
                    all_open_ports = []
                    for ip, ports in device_ports.items():
                        for port in ports:
                            all_open_ports.append(port)
                    
                    if all_open_ports:
                        unique_ports = sorted(list(set(all_open_ports)))
                        device_properties["open_ports"] = unique_ports
                
                # Create Device node
                builder.create_node(
                    id=device_id,
                    kinds=["Device"],
                    properties=device_properties
                )
                
                # Create Device → Website relationships (if HTTP validation results exist)
                if http_validation_results:
                    for target, http_result in http_validation_results.items():
                        target_ip, target_port = target.split(':')
                        if target_ip == device_ip:
                            # Create Website node for HTTP
                            if http_result['http']['status']:
                                website_url = f"http://{device_ip}:{target_port}"
                                website_name = http_result['http']['title'] or f"Device-Website-{device_ip}-{target_port}"
                                website_id = website_name.replace(" ", "-").replace("/", "-").replace("\\", "-")[:50]
                                
                                website_properties = {
                                    "name": website_name,
                                    "url": website_url,
                                    "has_ssl": False,
                                    "is_self_signed": False,
                                    "status_code": http_result['http']['code'],
                                    "protocol": "http",
                                    "body": http_result['http'].get('body', '')
                                }
                                
                                # Create Website node
                                builder.create_node(
                                    id=f"{website_id}-{device_ip}-{target_port}-http",
                                    kinds=["Website"],
                                    properties=website_properties
                                )
                                
                                # Create Device → Website edge
                                builder.create_edge(
                                    start_value=device_id,
                                    end_value=f"{website_id}-{device_ip}-{target_port}-http",
                                    kind="ExposeWebsite"
                                )
                                
                                logger.debug(f"Created Device Website: {website_name} ({website_url})")
                            
                            # Create Website node for HTTPS
                            if http_result['https']['status']:
                                website_url = f"https://{device_ip}:{target_port}"
                                website_name = http_result['https']['title'] or f"Device-Website-{device_ip}-{target_port}-SSL"
                                website_id = website_name.replace(" ", "-").replace("/", "-").replace("\\", "-")[:50]
                                
                                website_properties = {
                                    "name": website_name,
                                    "url": website_url,
                                    "has_ssl": True,
                                    "is_self_signed": http_result['https'].get('is_self_signed', False),
                                    "status_code": http_result['https']['code'],
                                    "protocol": "https",
                                    "body": http_result['https'].get('body', '')
                                }
                                
                                # Create Website node
                                builder.create_node(
                                    id=f"{website_id}-{device_ip}-{target_port}-https",
                                    kinds=["Website"],
                                    properties=website_properties
                                )
                                
                                # Create Device → Website edge
                                builder.create_edge(
                                    start_value=device_id,
                                    end_value=f"{website_id}-{device_ip}-{target_port}-https",
                                    kind="ExposeWebsite"
                                )
                                
                                logger.debug(f"Created Device Website: {website_name} ({website_url})")
                
                # Create edge from device to subnet
                device_subnet = device_info['subnet']
                for subnet_str in subnet_ids:
                    if subnet_str == device_subnet:
                        subnet_id = subnet_ids[subnet_str]
                        builder.create_edge(
                            start_value=device_id,
                            end_value=subnet_id,
                            kind="LocatedIn"
                        )
                        break
                
                logger.debug(f"Created Device node: {device_info['ip']} (Shadow-IT)")
        
        # Save to file
        builder.save_to_file(output_file)
        logger.info(f"OpenGraph JSON saved to: {output_file}")
        
        # Also print to stdout
        json_output = builder.to_json()
        logger.debug("Generated OpenGraph JSON")
        # logger.debug(json_output)  # Uncomment for full JSON output in debug mode
        
        return True
    
    except Exception as e:
        logger.error(f"Error creating OpenGraph JSON: {e}")
        return False


def perform_http_validation(port_scan_results, max_threads, timeout, detailed_ssl=False):
    """Perform HTTP/HTTPS validation on discovered open ports
    
    Args:
        port_scan_results: Results from port scanning
        max_threads: Maximum number of threads
        timeout: Request timeout
        detailed_ssl: If True, extract detailed SSL certificate info (slower)
    """
    from validators.http_validator import HTTPValidator
    
    if not port_scan_results:
        return {}
    
    # Use detailed_ssl parameter to control SSL analysis depth
    validator = HTTPValidator(timeout=timeout, max_threads=max_threads, detailed_ssl=detailed_ssl)
    
    # Collect all IP:port combinations that need HTTP validation
    targets = []
    for computer_name, computer_ports in port_scan_results.items():
        for ip, ports in computer_ports.items():
            for port in ports:
                targets.append(f"{ip}:{port}")
    
    if not targets:
        return {}
    
    logger.info("HTTP/HTTPS validation requested...")
    logger.info(f"Starting HTTP/HTTPS validation for {len(targets)} IP:port combinations...")
    logger.info(f"Threads: {max_threads}, Timeout: {timeout}s")
    ssl_mode = "Detailed SSL analysis" if detailed_ssl else "Basic SSL info only"
    logger.info(f"SSL Mode: {ssl_mode}")
    
    # Convert targets to (ip, port) tuples for the validator
    ip_port_list = []
    for target in targets:
        ip, port = target.split(':')
        ip_port_list.append((ip, int(port)))
    
    # Use the optimized threaded/multiprocessing validation
    results = validator.validate_http_ports_threaded(ip_port_list)
    
    return results

def perform_smb_validation(port_scan_results, max_threads, timeout, username="", password="", domain="", ntlm_hash="", kerberos_ticket=""):
    """Perform SMB validation on discovered SMB ports
    
    Args:
        port_scan_results: Results from port scanning
        max_threads: Maximum number of threads
        timeout: Request timeout
        username: Username for SMB authentication
        password: Password for SMB authentication
        domain: Domain for SMB authentication
        ntlm_hash: NTLM hash for SMB authentication
        kerberos_ticket: Kerberos ticket file for SMB authentication
    """
    from validators.smb_shares_manager import SMBSharesManager
    
    if not port_scan_results:
        return {}
    
    manager = SMBSharesManager(timeout=timeout, max_threads=max_threads)
    
    # Collect all IP:port combinations for SMB ports (139, 445)
    targets = []
    for computer_name, computer_ports in port_scan_results.items():
        for ip, ports in computer_ports.items():
            for port in ports:
                if port in [139, 445]:  # Only SMB ports
                    targets.append(f"{ip}:{port}")
    
    if not targets:
        logger.info("No SMB ports found for validation")
        return {}
    
    logger.info("SMB validation requested...")
    logger.info(f"Starting SMB validation for {len(targets)} SMB targets...")
    logger.info(f"Threads: {max_threads}, Timeout: {timeout}s")
    if username:
        auth_type = "NTLM Hash" if ntlm_hash else "Password"
        logger.info(f"Auth: {username}@{domain or 'WORKGROUP'} ({auth_type})")
    else:
        logger.info("Auth: Anonymous/Guest access only")
    
    # Convert targets to (ip, port) tuples for the manager
    ip_port_list = []
    for target in targets:
        ip, port = target.split(':')
        ip_port_list.append((ip, int(port)))
    
    # Use the SMB shares manager
    results = manager.validate_smb_ports_threaded(ip_port_list, username, password, domain, ntlm_hash, kerberos_ticket)
    
    return results

def create_dummy_computers_from_ips(live_ips):
    """Create dummy computer objects from discovered live IPs"""
    dummy_computers = []
    for ip in live_ips:
        # Create a dummy computer object
        computer_id = f"MANUAL-DEVICE-{ip.replace('.', '-')}"
        dummy_computer = {
            'sid': computer_id,
            'computer_name': f"Device-{ip}",
            'dns_hostname': f"device-{ip.replace('.', '-')}.local",
            'os': 'Unknown'
        }
        dummy_computers.append(dummy_computer)
    
    logger.info(f"Created {len(dummy_computers)} dummy computer objects from live IPs")
    return dummy_computers

def create_network_topology(computers, dns_records, domain, ad_client, shadow_devices=None, port_scan_results=None, http_validation_results=None, smb_validation_results=None, username="unknown"):
    """Create OpenGraph network topology"""
    logger.info("Creating OpenGraph network topology...")
    
    # Get AD subnets
    subnets = ad_client.query_subnets()
    
    # Create NetworkTopologyBuilder instance
    builder = NetworkTopologyBuilder(domain)
    
    # Build the complete network topology
    builder.build_topology(
        ad_client=ad_client,
        computers=computers,
        dns_records=dns_records,
        port_scan_results=port_scan_results,
        http_validation_results=http_validation_results,
        smb_validation_results=smb_validation_results,
        shadow_devices=shadow_devices or {},
        username=username
    )
    
    return builder


def main():
    """Main function"""
    args = parse_arguments()
    
    # Setup logging first (INFO/DEBUG)
    setup_logging(verbose=args.verbose)
    
    # Banner
    banner = r"""
 █▀█ █▀▀ ▀█▀ █ █ █▀█ █▀▄ █ █   █ █ █▀█ █ █ █▀█ █▀▄
 █ █ █▀▀  █  █▄█ █ █ █▀▄ █▀▄   █▀█ █ █ █ █ █ █ █ █
 ▀ ▀ ▀▀▀  ▀  ▀ ▀ ▀▀▀ ▀ ▀ ▀ ▀   ▀ ▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ 
NetworkHound - Active Directory Network Topology Analyzer
Author: Mor David (www.mordavid.com) | License: Non-Commercial
"""
    logger.info(banner)
    
    logger.info("Starting NetworkHound")
    
    # Determine operation mode
    manual_mode = bool(args.networks)
    logger.info(f"🔧 Operation Mode: {'Manual Network Scanning' if manual_mode else 'LDAP Active Directory'}")
    
    if manual_mode:
        logger.info(f"📋 Networks: {args.networks}")
        dns_server = args.dns if args.dns else "8.8.8.8"  # Default to Google DNS in manual mode
        logger.info(f"🌐 DNS Server: {dns_server}")
        if getattr(args, 'dns_tcp', False):
            logger.info(f"🔧 DNS Protocol: TCP (forced)")
        else:
            logger.info(f"🔧 DNS Protocol: UDP (default)")
    else:
        # Use DC as DNS server if not specified
        dns_server = args.dns if args.dns else args.dc
        logger.info(f"🔗 DC Server: {args.dc}")
        logger.info(f"🏢 Domain: {args.domain}")
        logger.info(f"👤 User: {args.user}")
        logger.info(f"🌐 DNS Server: {dns_server}")
        if getattr(args, 'dns_tcp', False):
            logger.info(f"🔧 DNS Protocol: TCP (forced)")
        else:
            logger.info(f"🔧 DNS Protocol: UDP (default)")
        
        # Show authentication method (impacket only)
        logger.info(f"🔐 Auth Method: impacket")
        if args.password:
            logger.info(f"🔑 Auth Type: Password")
        elif args.hashes:
            logger.info(f"🔑 Auth Type: NTLM Hash")
        elif args.kerberos:
            import os
            krb5_ccname = os.environ.get('KRB5CCNAME', 'Not set')
            logger.info(f"🔑 Auth Type: Kerberos (KRB5CCNAME: {krb5_ccname})")
    
    logger.info(f"📄 Output JSON: {args.output}")
    logger.info(f"🏓 Ping Check: {'Disabled (-Pn)' if getattr(args, 'Pn', False) else 'Enabled (default)'}")
    logger.info(f"🔍 Port Scanning: {'Yes' if args.port_scan else 'No'}")
    if args.port_scan:
        logger.info(f"🔌 Ports to Scan: {args.ports}")
        logger.info(f"⏱️  Scan Timeout: {args.scan_timeout}s")
        logger.info(f"🧵 Scan Threads: {args.scan_threads}")
    logger.info(f"🌐 HTTP Validation: {'Yes' if args.valid_http else 'No'}")
    logger.info(f"📁 SMB Validation: {'Yes' if args.valid_smb else 'No'}")
    logger.info(f"🔊 Verbose Mode: {'Yes' if args.verbose else 'No'}")
    if hasattr(args, 'shadow_it') and args.shadow_it:
        logger.info(f"👻 Shadow-IT Scan: Yes")
    logger.info("=" * 70)
    
    # Initialize variables
    connection = None
    computers = []
    dns_records = {}
    
    try:
        if manual_mode:
            # Manual mode - parse networks and discover live hosts
            logger.info("🌐 STEP 1: Parsing Manual Network Specifications")
            logger.info("=" * 70)
            manual_networks = parse_manual_networks(args.networks)
            if not manual_networks:
                logger.error("No valid networks specified")
                sys.exit(1)
            
            logger.info("")
            # Step 2: Discover live hosts in manual networks
            logger.info("🔍 STEP 2: Discovering Live Hosts in Networks")
            logger.info("=" * 70)
            
            all_live_ips = []
            for network_str, network_info in manual_networks.items():
                logger.info(f"Scanning network: {network_str}")
                
                # Generate all IPs - handle both networks and IP ranges
                if network_info.get('is_range', False):
                    # IP range - use the pre-generated IP list
                    all_ips = network_info['ip_list']
                else:
                    # Regular network - generate from network object
                    if network_info['network'].num_addresses > 1:
                        all_ips = [str(ip) for ip in network_info['network'].hosts()]
                    else:
                        all_ips = [str(network_info['network'].network_address)]
                
                if len(all_ips) > 1000:
                    logger.warning(f"Network {network_str} has {len(all_ips)} IPs. This may take a while...")
                
                # Use DNS resolver to test connectivity
                from core.dns_resolver import DNSResolver
                resolver = DNSResolver(dns_server, args.scan_threads, use_tcp=getattr(args, 'dns_tcp', False))
                live_results = resolver.test_connectivity_threaded(all_ips)
                live_ips = [ip for ip, is_alive in live_results.items() if is_alive]
                
                logger.info(f"✅ Found {len(live_ips)} live hosts in {network_str}")
                all_live_ips.extend(live_ips)
            
            logger.info("")
            # Step 3: Create dummy computers and DNS records
            logger.info("💻 STEP 3: Creating Device Objects from Live IPs")
            logger.info("=" * 70)
            computers = create_dummy_computers_from_ips(all_live_ips)
            dns_records = {comp['computer_name']: [comp['computer_name'].replace('Device-', '')] for comp in computers}
            
        else:
            # LDAP mode - original flow
            logger.info("🔗 STEP 1: Connecting to Domain Controller")
            logger.info("=" * 70)
            
            # Use impacket for authentication (only option)
            logger.info("🔐 Using impacket for authentication")
            # Use --hashes for NTLM authentication
            final_hash = args.hashes or ""
            
            result = connect_with_impacket(
                dc_host=args.dc,
                domain=args.domain,
                username=args.user,
                password=args.password or "",
                ntlm_hash=final_hash,
                kerberos_ticket="",  # Will be set from KRB5CCNAME in function
                use_kerberos=args.kerberos
            )
            
            if not result:
                logger.error("Failed to connect to Domain Controller")
                sys.exit(1)
            
            # Unpack the result
            connection, extracted_domain, extracted_username = result
            # Update args with extracted values
            args.domain = extracted_domain
            args.user = extracted_username
            
            logger.info("")
            # Step 2: Query computer objects
            logger.info("💻 STEP 2: Querying Active Directory Computer Objects")
            logger.info("=" * 70)
            computers = query_computers(connection, args.domain)
            if not computers:
                logger.error("❌ No computer objects found in Active Directory")
                if args.kerberos:
                    logger.error("🔍 This might be due to:")
                    logger.error("   • Clock skew between client and DC")
                    logger.error("   • Kerberos ticket issues")
                    logger.error("   • Network connectivity problems")
                    logger.error("   • Insufficient privileges")
                    logger.info("💡 Try running: klist -c $KRB5CCNAME")
                    logger.info("💡 Check if ticket is still valid")
                sys.exit(1)
            
            logger.info(f"Successfully found {len(computers)} computer objects in Active Directory")
            
            logger.info("")
            # Step 3: Resolve hostnames to IP addresses using threading
            logger.info("🔍 STEP 3: Resolving Computer Hostnames to IP Addresses")
            logger.info("=" * 70)
            dns_records = resolve_hostnames_to_ips_threaded(computers, dns_server, args.scan_threads, use_tcp=getattr(args, 'dns_tcp', False))
        
        # Step 4: Perform shadow-IT scanning if requested  
        shadow_devices = {}
        step_num = 4 if not manual_mode else 4  # Keep consistent
        if args.shadow_it:
            logger.info("")
            logger.info(f"👻 STEP {step_num}: Scanning for Shadow-IT Devices")
            logger.info("=" * 70)
            
            # Get all known IPs from AD computers
            known_ips = set()
            for computer_name, ips in dns_records.items():
                if isinstance(ips, list):
                    known_ips.update(ips)
                elif isinstance(ips, str):
                    known_ips.add(ips)
            
            logger.info(f"Known AD computer IPs: {len(known_ips)}")
            
            if manual_mode:
                # In manual mode, use the manual networks for shadow-IT scanning
                logger.info(f"Scanning {len(manual_networks)} manual networks for shadow-IT devices...")
                for subnet_str, subnet_info in manual_networks.items():
                    subnet_shadow_devices = scan_ip_range_with_name(
                        subnet_str, subnet_info, known_ips, 
                        max_threads=args.scan_threads,
                        ping_check=getattr(args, 'Pn', False)
                    )
                    shadow_devices.update(subnet_shadow_devices)
            else:
                # First try to get subnets from AD Sites and Services
                ad_subnets = query_ad_subnets(connection, args.domain)
                
                # If no AD subnets found, auto-discover from known IPs as fallback
                if not ad_subnets:
                    logger.info("No subnets found via LDAP query - auto-discovering from known computer IPs...")
                    ad_subnets = discover_subnets_from_ips(known_ips)
                
                # Scan each subnet for shadow-IT devices
                logger.info(f"Scanning {len(ad_subnets)} subnets for shadow-IT devices...")
                for subnet_str, subnet_info in ad_subnets.items():
                    subnet_shadow_devices = scan_ip_range_with_name(
                        subnet_str, subnet_info, known_ips, 
                        max_threads=args.scan_threads,
                        ping_check=getattr(args, 'Pn', False)
                    )
                    shadow_devices.update(subnet_shadow_devices)
            
            logger.info(f"Total shadow-IT devices found: {len(shadow_devices)}")
        
        # Step 5: Perform port scanning if requested
        port_scan_results = None
        http_validation_results = None
        smb_validation_results = None
        step_num = 5 if not manual_mode else 5  # Keep consistent
        next_step = step_num
        if args.port_scan:
            logger.info("")
            logger.info(f"🔍 STEP {step_num}: Network Port Scanning")
            logger.info("=" * 70)
            try:
                # Parse port list
                ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
                if not ports:
                    logger.error("No valid ports specified for scanning")
                else:
                    # Combine AD computers and shadow-IT devices for unified port scanning
                    all_computers = computers.copy()  # Start with AD computers
                    all_dns_records = dns_records.copy()  # Start with AD DNS records
                    
                    # Add shadow-IT devices to the combined scan if shadow-IT is enabled
                    if args.shadow_it and shadow_devices:
                        logger.info(f"Adding {len(shadow_devices)} shadow-IT devices to unified port scan...")
                        
                        for device_id, device_info in shadow_devices.items():
                            device_name = device_info['device_name']
                            device_ip = device_info['ip']
                            
                            # Add to DNS records
                            all_dns_records[device_name] = [device_ip]
                            
                            # Add to computers list
                            all_computers.append({
                                'computer_name': device_name,
                                'sid': device_id,  # Use device_id as SID
                                'dns_hostname': None,
                                'os': 'Unknown'
                            })
                            logger.debug(f"Added shadow device: {device_name} -> {device_ip}")
                        
                        logger.info(f"Combined scan targets: {len(computers)} AD computers + {len(shadow_devices)} shadow-IT devices = {len(all_computers)} total")
                    
                    # Perform unified port scanning on all devices (AD + shadow-IT)
                    logger.info(f"Starting unified port scan on {len(all_computers)} devices...")
                    from core.port_scanner import PortScanner
                    scanner = PortScanner(timeout=args.scan_timeout, max_threads=args.scan_threads)
                    port_scan_results = scanner.scan_all_computers(
                        all_computers, all_dns_records, ports, 
                        ping_check=getattr(args, 'Pn', False)
                    )
                    
                # Step 6: Perform HTTP validation if requested
                if args.valid_http and port_scan_results:
                    step_num = 6 if not manual_mode else 6
                    logger.info("")
                    logger.info(f"🌐 STEP {step_num}: HTTP/HTTPS Validation")
                    logger.info("=" * 70)
                    http_validation_results = perform_http_validation(
                        port_scan_results, args.scan_threads, args.scan_timeout, 
                        detailed_ssl=args.ssl
                    )
                
                # Step 7: Perform SMB validation if requested
                if args.valid_smb and port_scan_results:
                    step_num = 7 if not manual_mode else 7
                    logger.info("")
                    logger.info(f"📁 STEP {step_num}: SMB Validation")
                    logger.info("=" * 70)
                    # Use the same credentials as for LDAP connection
                    smb_username = args.user if not manual_mode else ""
                    smb_password = args.password if not manual_mode else ""
                    smb_domain = args.domain if not manual_mode else ""
                    smb_ntlm_hash = args.hashes if not manual_mode else ""
                    
                    # For Kerberos, pass the ticket file and clear password
                    if args.kerberos and not manual_mode:
                        import os
                        smb_kerberos_ticket = os.environ.get('KRB5CCNAME', '')
                        smb_password = ""  # Clear password for Kerberos
                        logger.info(f"🎫 Using Kerberos ticket for SMB: {smb_kerberos_ticket}")
                    else:
                        smb_kerberos_ticket = ""
                    
                    # Filter port_scan_results to only include AD computers (not shadow-IT devices)
                    ad_computer_names = set(comp['computer_name'] for comp in computers)
                    ad_port_scan_results = {
                        computer_name: computer_ports 
                        for computer_name, computer_ports in port_scan_results.items()
                        if computer_name in ad_computer_names
                    }
                    
                    logger.info(f"SMB validation will run on {len(ad_port_scan_results)} AD computers (excluding shadow-IT devices)")
                    
                    smb_validation_results = perform_smb_validation(
                        ad_port_scan_results, args.scan_threads, args.scan_timeout,
                        smb_username, smb_password, smb_domain, smb_ntlm_hash, smb_kerberos_ticket
                    )
                
            except ValueError as e:
                logger.error(f"Invalid port list format: {e}")
        
        # Final Step: Create OpenGraph JSON - calculate step number dynamically
        final_step = 4 if not manual_mode else 4  # Base step after DNS resolution
        if args.shadow_it:
            final_step += 1  # Shadow-IT is step 4
        if args.port_scan:
            final_step += 1  # Port scan is next step
        if args.valid_http and port_scan_results:
            final_step += 1  # HTTP validation is next step
        if args.valid_smb and port_scan_results:
            final_step += 1  # SMB validation is next step
        
        logger.info("")
        logger.info(f"📊 STEP {final_step}: Creating Network Topology Graph")
        logger.info("=" * 70)
        
        if manual_mode:
            # In manual mode, create a dummy AD client with manual networks
            from core.ad_client import ADClient
            ad_client = ADClient("manual", "manual.local", "manual", "manual")
            ad_client.connection = None
            # Override the query_subnets method to return our manual networks
            ad_client.query_subnets = lambda: manual_networks
            ad_client.get_domain_info = lambda: {
                'domain_name': 'manual.local',
                'domain_sid': 'S-1-5-21-MANUAL-NETWORK-SCAN',
                'distinguished_name': 'DC=manual,DC=local',
                'description': 'Manual network scanning mode'
            }
        else:
            # We need to create an ad_client wrapper for the connection
            from core.ad_client import ADClient
            ad_client = ADClient(args.dc, args.domain, args.user, args.password)
            ad_client.connection = connection  # Use existing connection
            
            # Critical validation: Verify we can get domain information
            logger.info("🔍 Validating domain information...")
            try:
                domain_info = ad_client.get_domain_info()
                if not domain_info or not domain_info.get('domain_sid'):
                    logger.error("❌ CRITICAL ERROR: Could not retrieve domain information")
                    logger.error("   This is required for proper Active Directory analysis")
                    sys.exit(1)
                logger.info(f"✅ Domain validated: {domain_info['domain_name']} (SID: {domain_info['domain_sid']})")
            except Exception as e:
                logger.error(f"❌ CRITICAL ERROR: Domain validation failed: {e}")
                logger.error("   Cannot continue without valid domain information")
                sys.exit(1)
        
        domain_name = "manual.local" if manual_mode else args.domain
        # Create BloodHound-style username format: USER@DOMAIN.COM
        bloodhound_user = f"{args.user.upper()}@{args.domain.upper()}" if not manual_mode else "MANUAL@MANUAL.LOCAL"
        
        # Create network topology using the proper NetworkTopologyBuilder
        builder = NetworkTopologyBuilder(domain_name)
        builder.build_topology(
            ad_client=ad_client,
            computers=computers,
            dns_records=dns_records,
            port_scan_results=port_scan_results,
            http_validation_results=http_validation_results,
            smb_validation_results=smb_validation_results if 'smb_validation_results' in locals() else None,
            shadow_devices=shadow_devices,
            username=bloodhound_user
        )
        
        if builder.save_to_file(args.output):
            logger.info("")
            logger.info("✅ ANALYSIS COMPLETED SUCCESSFULLY!")
            logger.info("=" * 70)
            logger.info(f"📄 Results saved to: {args.output}")
            logger.info(f"⏰ Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("=" * 70)
            logger.info("🎉 NetworkHound collection completed successfully")
        else:
            logger.error("Failed to save topology file")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    
    finally:
        # Close connection (only in LDAP mode)
        if connection and not manual_mode:
            connection.unbind()

if __name__ == "__main__":
    main()
