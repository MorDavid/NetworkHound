#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
DNS resolution utilities with multiple resolution methods
"""

import socket
import subprocess
import ipaddress
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger('NetworkHound.DNSResolver')

# Try to import dnspython for enhanced DNS resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSResolver:
    """DNS resolver with multiple resolution methods"""
    
    def __init__(self, dns_server=None, max_threads=10, use_tcp=False):
        self.dns_server = dns_server
        self.max_threads = max_threads
        self.use_tcp = use_tcp
    
    def test_connectivity(self, hostname):
        """Test if computer is reachable via ping"""
        try:
            # Use ping command (works on both Windows and Linux)
            ping_cmd = ['ping', '-c', '1', '-W', '2', hostname]  # Linux/Mac
            import sys
            if sys.platform.startswith('win'):
                ping_cmd = ['ping', '-n', '1', '-w', '2000', hostname]  # Windows
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def resolve_single_computer(self, computer, test_connectivity=False):
        """Enhanced IP resolution for a single computer using multiple methods"""
        hostname = computer['dns_hostname'] if computer['dns_hostname'] else computer['computer_name']
        if not hostname:
            return {'ips': [], 'methods': [], 'connectivity': 'Unknown', 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        logger.debug(f"Resolving: {hostname}")
        computer_ips = []
        resolution_methods = []
        
        # Method 1: Standard socket resolution (primary IP)
        try:
            ip_address = socket.gethostbyname(hostname)
            if ip_address not in computer_ips:
                computer_ips.append(ip_address)
                resolution_methods.append("socket")
                logger.debug(f"Socket resolved {hostname} -> {ip_address}")
        except socket.gaierror as e:
            logger.debug(f"Socket failed for {hostname}: {e}")
        
        # Method 2: nslookup with specific DNS server (authoritative)
        if self.dns_server:
            try:
                nslookup_cmd = ['nslookup']
                # Add TCP flag if requested (some versions of nslookup support -vc for TCP)
                if self.use_tcp:
                    nslookup_cmd.extend(['-vc'])  # -vc = virtual circuit (TCP)
                nslookup_cmd.extend([hostname, self.dns_server])
                
                result = subprocess.run(nslookup_cmd, 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Address:' in line and not line.startswith('Server:'):
                            ip_address = line.split('Address:')[1].strip()
                            if (ip_address and not ip_address.endswith('#53') and 
                                ip_address not in computer_ips):
                                computer_ips.append(ip_address)
                                method_name = "nslookup-tcp" if self.use_tcp else "nslookup"
                                resolution_methods.append(method_name)
                                logger.debug(f"{method_name} found {hostname} -> {ip_address}")
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                logger.debug(f"nslookup failed for {hostname}: {e}")
        
        # Method 3: dnspython library (if available)
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                if self.dns_server:
                    resolver.nameservers = [self.dns_server]
                
                # Configure TCP if requested
                if self.use_tcp:
                    # Force TCP for all queries
                    import dns.query
                    import dns.message
                    
                    # Build DNS query message
                    query = dns.message.make_query(hostname, 'A')
                    
                    # Send query over TCP
                    response = dns.query.tcp(query, self.dns_server or resolver.nameservers[0], timeout=10)
                    
                    # Parse response
                    for rrset in response.answer:
                        for rr in rrset:
                            if rr.rdtype == dns.rdatatype.A:  # A record
                                ip = str(rr)
                                if ip not in computer_ips:
                                    computer_ips.append(ip)
                                    resolution_methods.append("dnspython-tcp")
                                    logger.debug(f"DNS library (TCP) found {hostname} -> {ip}")
                else:
                    # Use UDP (default)
                    answers = resolver.resolve(hostname, 'A')
                    for answer in answers:
                        ip = str(answer)
                        if ip not in computer_ips:
                            computer_ips.append(ip)
                            resolution_methods.append("dnspython")
                            logger.debug(f"DNS library found {hostname} -> {ip}")
            except Exception as e:
                logger.debug(f"DNS library failed for {hostname}: {e}")
        
        # Method 4: getaddrinfo for comprehensive address resolution
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr in addr_info:
                ip = addr[4][0]
                if ip not in computer_ips:
                    computer_ips.append(ip)
                    resolution_methods.append("getaddrinfo")
                    logger.debug(f"getaddrinfo found {hostname} -> {ip}")
        except socket.gaierror:
            pass
        
        # Method 5: Fallback to hostname without domain
        if computer['computer_name'] and computer['computer_name'] != hostname:
            try:
                ip_address = socket.gethostbyname(computer['computer_name'])
                if ip_address not in computer_ips:
                    computer_ips.append(ip_address)
                    resolution_methods.append("hostname-fallback")
                    logger.debug(f"Hostname fallback {computer['computer_name']} -> {ip_address}")
            except socket.gaierror as e:
                logger.debug(f"Hostname fallback failed for {computer['computer_name']}: {e}")
        
        # Test connectivity for first IP (only if requested)
        connectivity_status = "Unknown"
        if computer_ips and test_connectivity:
            is_online = self.test_connectivity(hostname)
            connectivity_status = "Online" if is_online else "Offline"
            logger.debug(f"Connectivity test: {connectivity_status}")
        
        return {
            'ips': computer_ips,
            'methods': resolution_methods,
            'connectivity': connectivity_status,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def resolve_computers_threaded(self, computers):
        """Enhanced IP resolution with threading support"""
        ip_records = {}
        resolution_stats = {
            'total_computers': len(computers),
            'successful_resolutions': 0,
            'total_ips_found': 0,
            'online_computers': 0,
            'methods_used': set()
        }
        
        logger.info(f"🔍 Starting threaded IP resolution for {len(computers)} computers...")
        logger.info(f"🌐 DNS Server: {self.dns_server if self.dns_server else 'System default'}")
        logger.info(f"🧵 Using {self.max_threads} concurrent threads")
        logger.info("=" * 70)
        
        # Use ThreadPoolExecutor for concurrent DNS resolution
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all DNS resolution tasks
            future_to_computer = {
                executor.submit(self.resolve_single_computer, computer, False): computer
                for computer in computers if computer['computer_name']
            }
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_computer):
                computer = future_to_computer[future]
                completed += 1
                
                logger.debug(f"[{completed}/{len(future_to_computer)}] Processing: {computer['computer_name']}")
                
                try:
                    resolution_result = future.result()
                    
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
                except Exception as e:
                    logger.debug(f"Error resolving {computer['computer_name']}: {e}")
        
        # Print final statistics
        logger.info("=" * 70)
        logger.info("📊 THREADED RESOLUTION STATISTICS")
        logger.info("=" * 70)
        logger.info(f"Total computers processed: {resolution_stats['total_computers']}")
        logger.info(f"Successful resolutions: {resolution_stats['successful_resolutions']}")
        logger.info(f"Total IP addresses found: {resolution_stats['total_ips_found']}")
        logger.info(f"Online computers: {resolution_stats['online_computers']}")
        logger.info(f"Success rate: {(resolution_stats['successful_resolutions']/resolution_stats['total_computers'])*100:.1f}%")
        logger.info(f"Methods used: {', '.join(sorted(resolution_stats['methods_used']))}")
        logger.info(f"Average IPs per computer: {resolution_stats['total_ips_found']/max(resolution_stats['successful_resolutions'], 1):.1f}")
        logger.info(f"Threads used: {self.max_threads}")
        
        return ip_records
    
    def test_connectivity_threaded(self, hostnames):
        """Test connectivity to multiple hosts using threading"""
        if not hostnames:
            return {}
        
        logger.info(f"🏓 Starting threaded ping test for {len(hostnames)} hosts...")
        logger.info(f"🧵 Using {self.max_threads} concurrent threads")
        
        connectivity_results = {}
        
        # Use ThreadPoolExecutor for concurrent ping tests
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ping tasks
            future_to_hostname = {
                executor.submit(self.test_connectivity, hostname): hostname
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
        logger.info(f"📊 Ping test complete: {online_count}/{len(hostnames)} hosts online")
        
        return connectivity_results


def match_ips_to_subnets(ad_subnets, ip_records):
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
                    # Handle both regular networks and IP ranges
                    ip_belongs_to_subnet = False
                    
                    if subnet_info.get('is_range', False):
                        # IP range - check if IP is in the IP list
                        ip_belongs_to_subnet = ip_str in subnet_info.get('ip_list', [])
                    elif subnet_info['network'] is not None:
                        # Regular network - check if IP is in network
                        ip_belongs_to_subnet = ip in subnet_info['network']
                    
                    if ip_belongs_to_subnet:
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
