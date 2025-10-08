#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
Port scanning utilities with threading support
"""

import socket
import time
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from utils.config import COMMON_SERVICES
from .dns_resolver import DNSResolver

# Configure logging
logger = logging.getLogger('NetworkHound.PortScanner')


def scan_single_target(args):
    """Helper function for multiprocessing - scan one IP:port combination"""
    ip, port, timeout = args
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return (ip, port) if result == 0 else None
    except (socket.error, socket.timeout):
        return None


class PortScanner:
    """Port scanner with multiprocessing and threading support"""
    
    def __init__(self, timeout=3, max_threads=10, use_multiprocessing=True):
        self.timeout = timeout
        self.max_threads = max_threads
        self.use_multiprocessing = use_multiprocessing
        # Use more processes for better parallelism (up to CPU count or max_threads)
        self.max_processes = min(cpu_count() * 2, max_threads) if use_multiprocessing else 1
        self.dns_resolver = DNSResolver(max_threads=max_threads)
    
    def scan_port(self, ip, port):
        """Scan a single port on a target IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except (socket.error, socket.timeout):
            return None
    
    def scan_computer_ports_fast(self, computer_name, ips, ports):
        """Fast multiprocessing port scan for multiple IPs"""
        if not ips:
            return {}
        
        total_targets = len(ips) * len(ports)
        logger.debug(f"Fast scanning {computer_name} ({len(ips)} IPs × {len(ports)} ports = {total_targets} targets)")
        
        # Create all IP:port combinations
        scan_targets = [(ip, port, self.timeout) for ip in ips for port in ports]
        
        scan_results = {ip: [] for ip in ips}
        open_count = 0
        
        if self.use_multiprocessing and len(scan_targets) > 50:
            # Use multiprocessing for large scans
            logger.debug(f"   Using {self.max_processes} processes for multiprocessing...")
            
            with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
                # Submit all scan tasks
                future_to_target = {
                    executor.submit(scan_single_target, target): target 
                    for target in scan_targets
                }
                
                # Collect results as they complete
                completed = 0
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    ip, port, _ = target
                    completed += 1
                    
                    try:
                        result = future.result()
                        if result:
                            result_ip, result_port = result
                            scan_results[result_ip].append(result_port)
                            open_count += 1
                            logger.debug(f"   {result_ip}:{result_port} - OPEN")
                        
                        # Progress indicator for large scans
                        if completed % 100 == 0:
                            logger.debug(f"   Progress: {completed}/{total_targets} ({(completed/total_targets)*100:.1f}%)")
                            
                    except Exception as e:
                        logger.debug(f"   Error scanning {ip}:{port} - {e}")
        else:
            # Use threading for smaller scans
            logger.debug(f"   Using {self.max_threads} threads for threading...")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all scan tasks
                future_to_target = {
                    executor.submit(scan_single_target, target): target 
                    for target in scan_targets
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    ip, port, _ = target
                    
                    try:
                        result = future.result()
                        if result:
                            result_ip, result_port = result
                            scan_results[result_ip].append(result_port)
                            open_count += 1
                            logger.debug(f"   {result_ip}:{result_port} - OPEN")
                    except Exception as e:
                        logger.debug(f"   Error scanning {ip}:{port} - {e}")
        
        # Sort results and print summary
        for ip in scan_results:
            scan_results[ip] = sorted(scan_results[ip])
            if scan_results[ip]:
                logger.debug(f"   {ip}: {len(scan_results[ip])} open ports - {scan_results[ip]}")
            else:
                logger.debug(f"   {ip}: No open ports found")
        
        logger.debug(f"   Total: {open_count} open ports found")
        return scan_results
    
    def _scan_single_computer(self, computer, ip_records, ports, ping_check):
        """Helper function to scan a single computer (for parallel execution)"""
        computer_name = computer['computer_name']
        ips = ip_records.get(computer_name, [])
        
        if isinstance(ips, str):
            ips = [ips]
        
        if not ips:
            logger.debug(f"Skipping {computer_name} - No IPs resolved")
            return None
        
        logger.debug(f"Scanning {computer_name}")
        
        # Check ping connectivity (unless -Pn flag is used)
        # ping_check=True means -Pn is enabled (skip ping), False means check ping (default)
        if not ping_check:
            # Default behavior: check ping before scanning
            primary_ip = ips[0]
            is_online = self.dns_resolver.test_connectivity(primary_ip)
            if not is_online:
                logger.debug(f"   Ping failed to {primary_ip} - Skipping port scan")
                return None
            else:
                logger.debug(f"   Ping successful to {primary_ip} - Proceeding with port scan")
        else:
            # -Pn flag enabled: skip ping check, treat all hosts as online
            logger.debug(f"   Skipping ping check (-Pn enabled) - Treating host as online")
        
        # Scan ports for this computer
        computer_scan_results = self.scan_computer_ports_fast(computer_name, ips, ports)
        
        if computer_scan_results:
            return (computer_name, computer_scan_results, len(ips))
        return None
    
    def scan_all_computers(self, computers, ip_records, ports, ping_check=False):
        """Perform network port scanning on all computers in parallel"""
        logger.info("🔍 Starting network port scan...")
        logger.info(f"🔌 Ports to scan: {ports}")
        logger.info(f"⏱️  Timeout: {self.timeout}s, Threads: {self.max_threads}")
        logger.info("=" * 70)
        
        scan_results = {}
        scan_stats = {
            'computers_scanned': 0,
            'total_ips_scanned': 0,
            'total_open_ports': 0,
            'scan_start_time': time.time()
        }
        
        # Early return if no computers to scan
        if not computers or len(computers) == 0:
            logger.warning("⚠️  No computers to scan")
            logger.info("=" * 70)
            logger.info("📊 PORT SCAN STATISTICS")
            logger.info("=" * 70)
            logger.info(f"Computers scanned: 0")
            logger.info(f"Scan duration: 0.0 seconds")
            return scan_results
        
        # Parallel scanning using ThreadPoolExecutor
        # Ensure max_workers is at least 1
        max_workers = max(1, min(self.max_threads, len(computers)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all computer scan tasks
            future_to_computer = {
                executor.submit(self._scan_single_computer, computer, ip_records, ports, ping_check): computer
                for computer in computers
            }
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_computer):
                computer = future_to_computer[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        computer_name, computer_scan_results, num_ips = result
                        scan_results[computer_name] = computer_scan_results
                        
                        # Update statistics
                        scan_stats['computers_scanned'] += 1
                        scan_stats['total_ips_scanned'] += num_ips
                        for ip_ports in computer_scan_results.values():
                            scan_stats['total_open_ports'] += len(ip_ports)
                    
                    # Progress indicator
                    if completed % 10 == 0 or completed == len(computers):
                        logger.info(f"Progress: {completed}/{len(computers)} computers scanned ({(completed/len(computers))*100:.1f}%)")
                        
                except Exception as e:
                    logger.debug(f"Error scanning {computer.get('computer_name', 'unknown')}: {e}")
        
        # Print scan statistics
        scan_duration = time.time() - scan_stats['scan_start_time']
        logger.info("=" * 70)
        logger.info("📊 PORT SCAN STATISTICS")
        logger.info("=" * 70)
        logger.info(f"Computers scanned: {scan_stats['computers_scanned']}")
        logger.info(f"IP addresses scanned: {scan_stats['total_ips_scanned']}")
        logger.info(f"Total open ports found: {scan_stats['total_open_ports']}")
        logger.info(f"Scan duration: {scan_duration:.1f} seconds")
        logger.info(f"Average scan time per computer: {scan_duration/max(scan_stats['computers_scanned'], 1):.1f}s")
        
        return scan_results
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        return COMMON_SERVICES.get(port, f"Port-{port}")


def scan_ip_range_with_name(subnet_str, subnet_info, known_ips, max_threads=10, ping_check=False):
    """Scan IP range for shadow-IT devices not in Active Directory with explicit subnet name
    
    Args:
        subnet_str: Subnet string representation
        subnet_info: Dictionary with subnet information
        known_ips: Set of known IP addresses to exclude
        max_threads: Maximum number of threads
        ping_check: If True, skip ping check (same as -Pn flag)
    """
    logger.info(f"👻 Scanning IP range {subnet_str} for shadow-IT devices...")
    
    # Generate all IPs - handle both networks and IP ranges
    if subnet_info.get('is_range', False):
        # IP range - use the pre-generated IP list
        all_ips = [ipaddress.IPv4Address(ip) for ip in subnet_info['ip_list']]
    else:
        # Regular network - generate from network object
        subnet_network = subnet_info['network']
        all_ips = list(subnet_network.hosts())
    
    # Filter out known AD computer IPs
    unknown_ips = [str(ip) for ip in all_ips if str(ip) not in known_ips]
    known_in_subnet = [str(ip) for ip in all_ips if str(ip) in known_ips]
    
    logger.debug(f"   Subnet {subnet_str}: {len(all_ips)} total IPs")
    logger.debug(f"   Known AD computers in subnet: {len(known_in_subnet)} ({known_in_subnet[:5]}{'...' if len(known_in_subnet) > 5 else ''})")
    logger.debug(f"   Unknown IPs to scan: {len(unknown_ips)}")
    
    if not unknown_ips:
        return {}
    
    # Determine which IPs to include
    if not ping_check:
        # Default: ping sweep to find live hosts only
        logger.debug(f"   Performing ping sweep on {len(unknown_ips)} IPs...")
        dns_resolver = DNSResolver(max_threads=max_threads)
        live_devices = dns_resolver.test_connectivity_threaded(unknown_ips)
        
        # Filter only responsive IPs
        responsive_ips = [ip for ip, is_alive in live_devices.items() if is_alive]
        logger.info(f"✅ Found {len(responsive_ips)} responsive shadow-IT devices")
    else:
        # -Pn flag: skip ping, treat all unknown IPs as potential shadow-IT devices
        responsive_ips = unknown_ips
        logger.info(f"✅ Treating all {len(responsive_ips)} unknown IPs as shadow-IT devices (-Pn enabled)")
    
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


def scan_ip_range(subnet_info, known_ips, max_threads=10):
    """Legacy function for backward compatibility"""
    # Try to determine subnet name from network object
    if subnet_info.get('is_range', False):
        subnet_str = "IP-Range"
    else:
        subnet_str = str(subnet_info['network']) if subnet_info.get('network') else "Unknown"
    
    return scan_ip_range_with_name(subnet_str, subnet_info, known_ips, max_threads)
