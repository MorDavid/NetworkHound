#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
SMB Shares Manager - Consolidated SMB share functionality
Handles all SMB share operations including discovery, validation, and management
"""

import logging
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from utils.config import MAX_ERROR_LENGTH

# Configure logging
logger = logging.getLogger('NetworkHound.SMBSharesManager')

class SMBSharesManager:
    """Comprehensive SMB shares management class"""
    
    def __init__(self, timeout=5, max_threads=10, use_multiprocessing=True):
        self.timeout = timeout
        self.max_threads = max_threads
        self.use_multiprocessing = use_multiprocessing
        
    def discover_smb_shares(self, ip, port, username="", password="", domain="", ntlm_hash="", kerberos_ticket=""):
        """Discover SMB shares on a specific IP:port"""
        results = {
            'smb': {
                'status': False, 
                'version': None, 
                'shares': [], 
                'domain': None,
                'server_name': None,
                'os': None,
                'error': None,
                'auth_required': False,
                'guest_access': False,
                'accessible_shares': []
            }
        }
        
        # Only test SMB ports
        if port not in [139, 445]:
            results['smb']['error'] = f"Port {port} is not an SMB port"
            return results
        
        try:
            # For Kerberos authentication, try to resolve IP to hostname for proper SPN
            target_name = ip
            if kerberos_ticket:
                # Try common hostname patterns for domain controllers
                potential_hostnames = [
                    f"dc01.{domain}",
                    f"dc.{domain}",
                    f"dc1.{domain}",
                    f"hst1.{domain}",
                    f"hst2.{domain}",
                    f"hst3.{domain}",
                    f"host1.{domain}",
                    f"host2.{domain}",
                    f"host3.{domain}",
                    f"server.{domain}",
                    f"server1.{domain}",
                    f"server2.{domain}"
                ]
                
                import socket
                hostname_found = False
                
                # Try common DC hostnames first (more reliable than reverse DNS)
                for potential_hostname in potential_hostnames:
                    try:
                        resolved_ip = socket.gethostbyname(potential_hostname)
                        if resolved_ip == ip:
                            target_name = potential_hostname
                            hostname_found = True
                            logger.debug(f"Found matching hostname {potential_hostname} for IP {ip}")
                            break
                    except:
                        continue
                
                # If not found, try reverse DNS lookup as fallback
                if not hostname_found:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        if '.' not in hostname:
                            hostname = f"{hostname}.{domain}"
                        # Only use reverse DNS if it looks like a valid hostname
                        if not hostname.startswith('_') and 'gateway' not in hostname.lower():
                            target_name = hostname
                            hostname_found = True
                            logger.debug(f"Using reverse DNS hostname {hostname} for Kerberos SPN (IP: {ip})")
                    except:
                        pass
                
                if not hostname_found:
                    logger.debug(f"Could not resolve {ip} to hostname, using IP for SMB connection")
                    target_name = ip
            
            # Test basic SMB connection
            smbClient = SMBConnection(target_name, ip, timeout=self.timeout)
            
            # Try multiple authentication methods
            auth_success = False
            auth_method_used = None
            
            # Method 1: Try with provided credentials first (if available)
            if username and (password or ntlm_hash or kerberos_ticket):
                try:
                    if kerberos_ticket:
                        # Kerberos ticket authentication
                        logger.debug(f"🎫 Using Kerberos authentication for SMB: {kerberos_ticket}")
                        try:
                            # Set KRB5CCNAME environment variable for Kerberos authentication
                            import os
                            if os.path.isfile(kerberos_ticket):
                                os.environ['KRB5CCNAME'] = kerberos_ticket
                                logger.debug(f"Set KRB5CCNAME={kerberos_ticket}")
                            elif 'KRB5CCNAME' not in os.environ:
                                # If kerberos_ticket is not a file, assume it's already set in environment
                                logger.warning(f"KRB5CCNAME not set and {kerberos_ticket} is not a file")
                            
                            # Use Kerberos authentication with impacket
                            # For Kerberos, we need to use the actual DC as KDC, not the target IP
                            dc_host = ip  # Default to target IP
                            
                            # Simple DC detection: check if target has Kerberos port (88) open
                            import socket
                            try:
                                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                test_sock.settimeout(1)
                                if test_sock.connect_ex((ip, 88)) == 0:
                                    dc_host = ip  # Target is a DC
                                    logger.debug(f"Target {ip} has Kerberos port open, using as KDC")
                                else:
                                    # Target is not a DC, try to find the actual DC
                                    # Try common DC IPs in same subnet
                                    ip_parts = ip.split('.')
                                    if len(ip_parts) == 4:
                                        subnet_base = '.'.join(ip_parts[:3])
                                        for dc_last_octet in [1, 11, 10, 100]:  # Common DC IPs (prioritize .1 and .11)
                                            potential_dc = f"{subnet_base}.{dc_last_octet}"
                                            if potential_dc != ip:
                                                try:
                                                    test_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                    test_sock2.settimeout(1)
                                                    if test_sock2.connect_ex((potential_dc, 88)) == 0:
                                                        dc_host = potential_dc
                                                        logger.debug(f"Found DC at {potential_dc} for target {ip}")
                                                        test_sock2.close()
                                                        break
                                                    test_sock2.close()
                                                except:
                                                    pass
                                test_sock.close()
                            except:
                                pass
                            
                            logger.debug(f"Using KDC: {dc_host} for SMB target: {ip}")
                            smbClient.kerberosLogin(username, password, domain, lmhash='', nthash='', aesKey='', kdcHost=dc_host, useCache=True)
                            auth_method_used = f"Kerberos (ticket: {kerberos_ticket})"
                            logger.debug(f"✅ Kerberos SMB login successful for {username}@{domain}")
                        except Exception as kerb_error:
                            logger.warning(f"Kerberos SMB login failed: {kerb_error}")
                            # Fallback to NTLM if available
                            if ntlm_hash:
                                if ':' in ntlm_hash:
                                    lm_hash, nt_hash = ntlm_hash.split(':', 1)
                                else:
                                    lm_hash = ''
                                    nt_hash = ntlm_hash
                                try:
                                    smbClient.login(username, password, domain, lm_hash, nt_hash)
                                    auth_method_used = f"NTLM (fallback from Kerberos)"
                                except Exception as ntlm_error:
                                    logger.debug(f"NTLM fallback also failed: {ntlm_error}")
                                    raise Exception("Kerberos and NTLM authentication failed")
                            elif password:
                                try:
                                    smbClient.login(username, password, domain)
                                    auth_method_used = f"Password (fallback from Kerberos)"
                                except Exception as pass_error:
                                    logger.debug(f"Password fallback also failed: {pass_error}")
                                    raise Exception("Kerberos and password authentication failed")
                            else:
                                    raise Exception("Kerberos authentication failed and no fallback credentials available")
                    elif ntlm_hash:
                        # Split NTLM hash if provided as LM:NT
                        if ':' in ntlm_hash:
                            lm_hash, nt_hash = ntlm_hash.split(':', 1)
                        else:
                            lm_hash = ''
                            nt_hash = ntlm_hash
                        
                        smbClient.login(username, password, domain, lm_hash, nt_hash)
                    else:
                        smbClient.login(username, password, domain)
                    
                    auth_success = True
                    auth_method_used = "credentials"
                    logger.debug(f"SMB credential login successful to {ip}:{port}")
                    
                except Exception as cred_e:
                    logger.debug(f"SMB credential login failed to {ip}:{port}: {cred_e}")
                    # Fallback to anonymous methods if credentials fail
                    auth_success = False
            
            # Method 2: Try anonymous login (if credentials failed or not provided)
            if not auth_success:
                try:
                    smbClient.login('', '')  # Anonymous login
                    results['smb']['guest_access'] = True
                    auth_success = True
                    auth_method_used = "anonymous"
                    logger.debug(f"SMB anonymous login successful to {ip}:{port}")
                except Exception as anon_e:
                    logger.debug(f"SMB anonymous login failed to {ip}:{port}: {anon_e}")
                    
                    # Method 3: Try guest user
                    try:
                        smbClient.login('guest', '', '')
                        results['smb']['guest_access'] = True
                        auth_success = True
                        auth_method_used = "guest"
                        logger.debug(f"SMB guest login successful to {ip}:{port}")
                    except Exception as guest_e:
                        logger.debug(f"SMB guest login failed to {ip}:{port}: {guest_e}")
                        
                        # Method 4: Try null session
                        try:
                            smbClient.login(None, None, '')
                            results['smb']['guest_access'] = True
                            auth_success = True
                            auth_method_used = "null_session"
                            logger.debug(f"SMB null session successful to {ip}:{port}")
                        except Exception as null_e:
                            logger.debug(f"SMB null session failed to {ip}:{port}: {null_e}")
                            results['smb']['error'] = f"All authentication methods failed"
                            results['smb']['auth_required'] = True
            
            if auth_success:
                results['smb']['status'] = True
                results['smb']['auth_method'] = auth_method_used
                
                # Get server information
                try:
                    server_name = smbClient.getServerName()
                    if server_name:
                        results['smb']['server_name'] = server_name
                except:
                    pass
                
                try:
                    server_domain = smbClient.getServerDomain()
                    if server_domain:
                        results['smb']['domain'] = server_domain
                except:
                    pass
                
                try:
                    server_os = smbClient.getServerOS()
                    if server_os:
                        results['smb']['os'] = server_os
                except:
                    pass
                
                # Get SMB version/dialect
                try:
                    dialect = smbClient.getDialect()
                    if dialect == SMB2_DIALECT_002:
                        results['smb']['version'] = 'SMB2.0'
                    elif dialect == SMB2_DIALECT_21:
                        results['smb']['version'] = 'SMB2.1'
                    elif dialect == SMB2_DIALECT_30:
                        results['smb']['version'] = 'SMB3.0'
                    else:
                        results['smb']['version'] = f'SMB_DIALECT_{dialect}'
                except:
                    results['smb']['version'] = 'Unknown'
                
                # Enumerate shares
                results['smb']['shares'], results['smb']['accessible_shares'] = self._enumerate_shares(smbClient, ip, port)
            
            smbClient.close()
            
        except Exception as e:
            error_msg = str(e)[:MAX_ERROR_LENGTH]
            results['smb']['error'] = error_msg
            logger.debug(f"SMB connection failed to {ip}:{port}: {error_msg}")
        
        return results
    
    def _enumerate_shares(self, smbClient, ip, port):
        """Enumerate SMB shares and test accessibility"""
        try:
            shares = smbClient.listShares()
            share_list = []
            accessible_shares = []
            
            for share in shares:
                share_name = str(share['shi1_netname']).strip('\x00')
                share_info = {
                    'name': share_name,
                    'type': share['shi1_type'] if hasattr(share, 'shi1_type') else 0,
                    'remark': str(share['shi1_remark']).strip('\x00') if hasattr(share, 'shi1_remark') else '',
                    'accessible': False  # Default to not accessible
                }
                
                # Test actual access to each share (except IPC$)
                if share_name != 'IPC$':
                    try:
                        # Try to list the root directory of the share
                        smbClient.listPath(share_name, '*')
                        share_info['accessible'] = True
                        accessible_shares.append(share_info)
                        logger.debug(f"✅ Share {share_name} on {ip}:{port} is accessible")
                    except Exception as access_e:
                        share_info['access_error'] = str(access_e)[:MAX_ERROR_LENGTH]
                        logger.debug(f"❌ Share {share_name} on {ip}:{port} access denied: {access_e}")
                
                share_list.append(share_info)
            
            logger.debug(f"Found {len(share_list)} SMB shares on {ip}:{port} ({len(accessible_shares)} accessible)")
            return share_list, accessible_shares
            
        except Exception as e:
            # If share enumeration fails, still mark as successful connection
            # but note that shares couldn't be enumerated
            logger.debug(f"Share enumeration failed on {ip}:{port}: {e}")
            return [], []
    
    def validate_smb_ports_threaded(self, ip_port_list, username="", password="", domain="", ntlm_hash="", kerberos_ticket=""):
        """Validate SMB connectivity on multiple IP:port combinations using threading"""
        if not ip_port_list:
            return {}
        
        # Filter only SMB ports
        smb_targets = [(ip, port) for ip, port in ip_port_list if port in [139, 445]]
        
        if not smb_targets:
            logger.info("No SMB ports found for validation")
            return {}
        
        logger.info(f"Starting SMB validation for {len(smb_targets)} SMB targets...")
        logger.info(f"Threads: {self.max_threads}, Timeout: {self.timeout}s")
        
        smb_results = {}
        
        if self.use_multiprocessing and len(smb_targets) > 10:
            # Use multiprocessing for large datasets
            max_workers = min(cpu_count(), self.max_threads)
            logger.debug(f"Using multiprocessing with {max_workers} processes")
            
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Prepare arguments for worker processes
                worker_args = [
                    (ip, port, self.timeout, username, password, domain, ntlm_hash, kerberos_ticket)
                    for ip, port in smb_targets
                ]
                
                # Submit all SMB validation tasks
                future_to_target = {
                    executor.submit(self._smb_worker, args): f"{args[0]}:{args[1]}"
                    for args in worker_args
                }
                
                # Collect results as they complete
                completed = 0
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        smb_results[target] = result
                        self._log_smb_result(target, result, completed, len(smb_targets))
                    except Exception as e:
                        smb_results[target] = {
                            'smb': {'status': False, 'error': str(e)[:MAX_ERROR_LENGTH]}
                        }
                        logger.debug(f"[{completed}/{len(smb_targets)}] {target}: Validation error - {e}")
        else:
            # Use threading for smaller datasets
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all SMB validation tasks
                future_to_target = {
                    executor.submit(self.discover_smb_shares, ip, port, username, password, domain, ntlm_hash, kerberos_ticket): f"{ip}:{port}"
                    for ip, port in smb_targets
                }
                
                # Collect results as they complete
                completed = 0
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        smb_results[target] = result
                        self._log_smb_result(target, result, completed, len(smb_targets))
                    except Exception as e:
                        smb_results[target] = {
                            'smb': {'status': False, 'error': str(e)[:MAX_ERROR_LENGTH]}
                        }
                        logger.debug(f"[{completed}/{len(smb_targets)}] {target}: Validation error - {e}")
        
        # Summary
        smb_success = sum(1 for r in smb_results.values() if r['smb']['status'])
        auth_required = sum(1 for r in smb_results.values() if r['smb'].get('auth_required', False))
        guest_access = sum(1 for r in smb_results.values() if r['smb'].get('guest_access', False))
        
        logger.info(f"SMB validation results: {smb_success}/{len(smb_targets)} successful")
        logger.info(f"  - Guest access: {guest_access}")
        logger.info(f"  - Auth required: {auth_required}")
        
        return smb_results
    
    def _smb_worker(self, args):
        """Worker function for multiprocessing SMB validation"""
        ip, port, timeout, username, password, domain, ntlm_hash, kerberos_ticket = args
        
        # Create a temporary SMBSharesManager instance for this process
        manager = SMBSharesManager(timeout=timeout, use_multiprocessing=False)
        return manager.discover_smb_shares(ip, port, username, password, domain, ntlm_hash, kerberos_ticket)
    
    def _log_smb_result(self, target, result, completed, total):
        """Log SMB validation result"""
        smb_result = result['smb']
        
        if smb_result['status']:
            status = "✅"
            details = []
            
            if smb_result.get('version'):
                details.append(f"Ver: {smb_result['version']}")
            
            if smb_result.get('guest_access'):
                details.append("Guest OK")
            elif smb_result.get('auth_required'):
                details.append("Auth Required")
            
            if smb_result.get('shares'):
                share_count = len(smb_result['shares'])
                details.append(f"{share_count} shares")
            
            if smb_result.get('server_name'):
                details.append(f"Server: {smb_result['server_name']}")
            
            detail_str = " - " + ", ".join(details) if details else ""
            logger.debug(f"[{completed}/{total}] {target}: {status}SMB{detail_str}")
        else:
            status = "❌"
            error = smb_result.get('error', 'Unknown error')
            logger.debug(f"[{completed}/{total}] {target}: {status}SMB - {error}")

    def get_typical_shares_for_computer(self, computer_name, server_name=None):
        """Get typical Windows shares based on computer type"""
        shares = []
        
        # Determine if this is a Domain Controller
        is_dc = (computer_name and ('DC' in computer_name.upper() or computer_name.upper().startswith('DC'))) or \
                (server_name and ('DC' in server_name.upper()))
        
        if is_dc:
            # Domain Controller - add DC shares
            shares = [
                {'name': 'NETLOGON', 'remark': 'Logon server share', 'type': 0, 'accessible': True},
                {'name': 'SYSVOL', 'remark': 'Logon server share', 'type': 0, 'accessible': True},
                {'name': 'ADMIN$', 'remark': 'Remote Admin', 'type': 2147483648, 'accessible': False},
                {'name': 'C$', 'remark': 'Default share', 'type': 2147483648, 'accessible': False}
            ]
        else:
            # Regular workstation - add basic shares
            shares = [
                {'name': 'ADMIN$', 'remark': 'Remote Admin', 'type': 2147483648, 'accessible': False},
                {'name': 'C$', 'remark': 'Default share', 'type': 2147483648, 'accessible': False}
            ]
        
        return shares

    def create_fileshare_nodes_for_computer(self, computer, ip_addresses, smb_validation_results, username="unknown"):
        """Create FileShare node data for a computer based on SMB validation results"""
        computer_name = computer.get('computer_name', 'Unknown')
        fileshare_nodes = []
        fileshare_edges = []
        
        if not smb_validation_results:
            return fileshare_nodes, fileshare_edges
        
        # Collect unique shares from all IPs (avoid duplicates)
        unique_shares = {}
        smb_accessible = False
        primary_ip = ip_addresses[0] if ip_addresses else None
        
        # Check all IPs for SMB validation results
        for ip in ip_addresses:
            for port in [139, 445]:  # SMB ports
                target = f"{ip}:{port}"
                if target in smb_validation_results:
                    smb_result = smb_validation_results[target]['smb']
                    
                    total_shares = len(smb_result.get('shares', []))
                    accessible_shares = len(smb_result.get('accessible_shares', []))
                    logger.debug(f"Checking {target} - status: {smb_result['status']}, shares: {total_shares} found ({accessible_shares} accessible)")
                    
                    # If SMB connection was successful on any IP
                    if smb_result['status']:
                        smb_accessible = True
                        # Use accessible shares only, fallback to all shares if no accessible_shares key
                        shares_list = smb_result.get('accessible_shares', smb_result.get('shares', []))
                        
                        # If no shares found due to access denied, add typical Windows shares (only once)
                        if not shares_list and 'STATUS_ACCESS_DENIED' in str(smb_result.get('shares_error', '')) and not unique_shares:
                            logger.info(f"SMB connected to {computer_name} but share enumeration denied. Adding typical Windows shares.")
                            shares_list = self.get_typical_shares_for_computer(computer_name, smb_result.get('server_name'))
                        
                        # Add shares to unique collection (avoid duplicates)
                        for share in shares_list:
                            if share['name'] != 'IPC$':  # Skip IPC$
                                unique_shares[share['name']] = share
        
        # Create FileShare nodes only once per unique share
        if smb_accessible and unique_shares:
            logger.debug(f"Creating FileShare nodes for {computer_name} with {len(unique_shares)} unique shares")
            
            for share_name, share in unique_shares.items():
                # Create unique FileShare node ID (without IP to avoid duplicates)
                fileshare_id = f"FILESHARE-{computer['sid']}-{share_name}".upper()
                
                # Create FileShare node properties
                fileshare_node = {
                    "id": fileshare_id,
                    "kinds": ["FileShare"],
                    "properties": {
                        "name": share['name'],
                        "discovered_by": username,
                        "description": share.get('remark', ''),
                        "share_type": share.get('type', 0),
                        "computer_name": computer_name,
                        "ip_addresses": ip_addresses,
                        "accessible": share.get('accessible', True)
                    }
                }
                
                fileshare_nodes.append(fileshare_node)
                
                # Create ExposeInterface edge from computer to fileshare
                fileshare_edge = {
                    "start": {
                        "value": computer['sid'],
                        "match_by": "id"
                    },
                    "end": {
                        "value": fileshare_id,
                        "match_by": "id"
                    },
                    "kind": "ExposeInterface",
                    "properties": {
                        "protocol": "smb", 
                        "share_name": share['name'], 
                        "ip_addresses": ip_addresses
                    }
                }
                
                fileshare_edges.append(fileshare_edge)
                
                access_status = "✅ accessible" if share.get('accessible', True) else "❌ access denied"
                logger.debug(f"Created FileShare node: {share['name']} for {computer_name} ({access_status})")
        
        if len(fileshare_nodes) > 0:
            logger.info(f"Created {len(fileshare_nodes)} unique FileShare nodes for {computer_name}")
        else:
            logger.debug(f"No FileShare nodes created for {computer_name} - no accessible SMB shares found")
        
        return fileshare_nodes, fileshare_edges

    def add_user_info_to_fileshares(self, fileshare_nodes, user_info):
        """Add user discovery information to FileShare nodes"""
        for node in fileshare_nodes:
            if node['kinds'] == ['FileShare']:
                # Add discovery information to FileShare properties
                node['properties']['discovered_by'] = user_info.get('username', 'unknown')
                node['properties']['discovered_domain'] = user_info.get('domain', '')
                node['properties']['auth_method_used'] = user_info.get('auth_method', '')
                node['properties']['discovery_timestamp'] = user_info.get('discovery_time', '')
                node['properties']['scanner_tool'] = user_info.get('scanner', 'NetworkHound')
                node['properties']['discovery_context'] = f"Discovered via SMB enumeration using {user_info.get('auth_method', 'authentication')}"
        
        return fileshare_nodes


def validate_smb_ports(ip_port_list, username="", password="", domain="", ntlm_hash="", kerberos_ticket="", max_threads=10, timeout=5):
    """Convenience function for SMB validation"""
    manager = SMBSharesManager(timeout=timeout, max_threads=max_threads)
    return manager.validate_smb_ports_threaded(ip_port_list, username, password, domain, ntlm_hash, kerberos_ticket)


