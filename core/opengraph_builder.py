#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
OpenGraph JSON builder for network topology visualization
Author: Mor David (www.mordavid.com) | License: Non-Commercial
"""

import ipaddress
import logging
from opengraph.core import OpenGraphBuilder
from .ad_client import ADClient
from .dns_resolver import match_ips_to_subnets

# Configure logging
logger = logging.getLogger('NetworkHound.OpenGraphBuilder')


class NetworkTopologyBuilder:
    """Builds OpenGraph JSON from network scan results"""
    
    def __init__(self, domain):
        self.domain = domain
        self.builder = OpenGraphBuilder()
        self.site_ids = {}
        self.subnet_ids = {}
        self.domain_id = None
    
    def connect_to_existing_domain(self, domain_info):
        """Connect to existing Domain node instead of creating a new one"""
        if not domain_info:
            return
            
        # Use domain SID as the existing node ID
        domain_sid = domain_info.get('domain_sid')
        if not domain_sid:
            logger.warning("No domain SID found, cannot connect to Domain node")
            return
            
        # Store the domain ID for creating edges to sites
        self.domain_id = domain_sid
        logger.debug(f"Connected to existing Domain node: {domain_info['domain_name']} (SID: {domain_sid})")
    
    def create_site_nodes(self, subnets):
        """Create Site nodes from subnet information"""
        sites_created = set()
        
        for subnet_str, subnet_info in subnets.items():
            site_name = subnet_info['site']
            if site_name not in sites_created:
                site_id = f"SITE-{site_name.replace(' ', '-').replace('.', '-').upper()}"
                self.site_ids[site_name] = site_id
                
                self.builder.create_node(
                    id=site_id,
                    kinds=["Site"],
                    properties={
                        "name": site_name,
                        "domain": self.domain
                    }
                )
                sites_created.add(site_name)
                logger.debug(f"Created Site node: {site_name}")
                
                # Create edge from Site to Domain
                if self.domain_id:
                    self.builder.create_edge(
                        start_value=site_id,
                        end_value=self.domain_id,
                        kind="PartOfDomain"
                    )
                    logger.debug(f"Created edge: {site_name} -> Domain")
    
    def create_subnet_nodes(self, subnets):
        """Create Subnet nodes and link them to sites"""
        for subnet_str, subnet_info in subnets.items():
            subnet_id = f"SUBNET-{subnet_str.replace('/', '-').replace('.', '-').upper()}"
            self.subnet_ids[subnet_str] = subnet_id
            
            self.builder.create_node(
                id=subnet_id,
                kinds=["Subnet"],
                properties={
                    "name": subnet_str,  # Use IP/prefix as name instead of site name
                    "subnet": subnet_str,
                    "domain": self.domain,
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
            if site_name in self.site_ids:
                site_id = self.site_ids[site_name]
                self.builder.create_edge(
                    start_value=subnet_id,
                    end_value=site_id,
                    kind="PartOf"
                )
            
            logger.debug(f"Created subnet node: {subnet_str}")
    
    def create_website_node(self, ip, port, http_result, protocol):
        """Create a Website node from HTTP validation results"""
        website_url = f"{protocol}://{ip}:{port}"
        suffix = "-SSL" if protocol == "https" else ""
        website_name = http_result[protocol]['title'] or f"Website-{ip}-{port}{suffix}"
        
        website_properties = {
            "name": website_name,
            "url": website_url,
            "has_ssl": protocol == "https",
            "is_self_signed": http_result[protocol].get('is_self_signed', False) if protocol == "https" else False,
            "status_code": http_result[protocol]['code'],
            "protocol": protocol,
            "body": http_result[protocol].get('body', '')
        }
        
        # Add detailed SSL certificate information for HTTPS (only if detailed info is available)
        if protocol == "https" and 'ssl_certificate' in http_result[protocol]:
            ssl_cert = http_result[protocol]['ssl_certificate']
            
            # Check if this is detailed SSL info or just basic info
            has_detailed_ssl = len(ssl_cert) > 3  # Basic mode has only 2-3 properties
            
            if has_detailed_ssl:
                # Add comprehensive SSL certificate properties
                website_properties.update({
                # Basic certificate info (convert objects to strings)
                "ssl_subject_cn": ssl_cert.get('subject', {}).get('commonName', ''),
                "ssl_subject_org": ssl_cert.get('subject', {}).get('organizationName', ''),
                "ssl_subject_country": ssl_cert.get('subject', {}).get('countryName', ''),
                "ssl_issuer_cn": ssl_cert.get('issuer', {}).get('commonName', ''),
                "ssl_issuer_org": ssl_cert.get('issuer', {}).get('organizationName', ''),
                "ssl_issuer_country": ssl_cert.get('issuer', {}).get('countryName', ''),
                "ssl_version": ssl_cert.get('version', 'Unknown'),
                "ssl_serial_number": ssl_cert.get('serial_number', 'Unknown'),
                
                # Certificate fingerprints
                "ssl_sha1_fingerprint": ssl_cert.get('sha1_fingerprint', ''),
                "ssl_sha256_fingerprint": ssl_cert.get('sha256_fingerprint', ''),
                "ssl_md5_fingerprint": ssl_cert.get('md5_fingerprint', ''),
                
                # Validity and dates
                "ssl_valid_from": ssl_cert.get('valid_from', ''),
                "ssl_valid_until": ssl_cert.get('valid_until', ''),
                "ssl_is_expired": ssl_cert.get('is_expired', False),
                "ssl_days_until_expiry": ssl_cert.get('days_until_expiry'),
                "ssl_days_since_issued": ssl_cert.get('days_since_issued'),
                "ssl_validity_period_days": ssl_cert.get('validity_period_days'),
                
                # Subject Alternative Names (enhanced)
                "ssl_subject_alt_names": ssl_cert.get('subject_alt_names', []),
                "ssl_san_dns_names": ssl_cert.get('san_dns_names', []),
                "ssl_san_ip_addresses": ssl_cert.get('san_ip_addresses', []),
                "ssl_san_email_addresses": ssl_cert.get('san_email_addresses', []),
                
                # Certificate chain
                "ssl_certificate_chain_length": ssl_cert.get('certificate_chain_length', 1),
                "ssl_is_ca_certificate": ssl_cert.get('is_ca_certificate', False),
                
                # Cipher and protocol info
                "ssl_cipher_suite": ssl_cert.get('cipher_suite', 'Unknown'),
                "ssl_cipher_protocol": ssl_cert.get('cipher_protocol', 'Unknown'),
                "ssl_cipher_bits": ssl_cert.get('cipher_bits', 0),
                "ssl_protocol_version": ssl_cert.get('protocol_version', 'Unknown'),
                
                # Security analysis (convert objects to primitives)
                "ssl_security_level": ssl_cert.get('security_analysis', {}).get('security_level', 'Unknown'),
                "ssl_security_warnings": ssl_cert.get('security_analysis', {}).get('warnings', []),
                "ssl_security_recommendations": ssl_cert.get('security_analysis', {}).get('recommendations', []),
                
                # Public key info (convert objects to primitives)
                "ssl_public_key_algorithm": ssl_cert.get('public_key_info', {}).get('algorithm', 'Unknown'),
                "ssl_public_key_size": ssl_cert.get('public_key_info', {}).get('key_size', 'Unknown'),
                
                # Certificate extensions (convert to string representation)
                "ssl_extensions_count": len(ssl_cert.get('extensions', {})),
                "ssl_extensions_list": list(ssl_cert.get('extensions', {}).keys()),
                
                # Error handling
                "ssl_certificate_error": ssl_cert.get('error')
                })
            else:
                # Basic SSL info only (fast mode)
                website_properties.update({
                    "ssl_cipher_suite": ssl_cert.get('cipher_suite', 'Unknown'),
                    "ssl_protocol_version": ssl_cert.get('protocol_version', 'Unknown')
                })
            
            # Update is_self_signed from detailed certificate info if available
            if 'is_self_signed' in ssl_cert:
                website_properties['is_self_signed'] = ssl_cert['is_self_signed']
        
        # Create Website node with PROTOCOL-IP-PORT format (all uppercase)
        node_id = f"{protocol.upper()}-{ip.replace('.', '-')}-{port}".upper()
        
        self.builder.create_node(
            id=node_id,
            kinds=["Website"],
            properties=website_properties
        )
        
        logger.debug(f"Created Website node: {website_name} ({website_url})")
        return node_id
    
    def create_computer_nodes(self, computers, dns_records, port_scan_results=None, http_validation_results=None, smb_validation_results=None, subnets=None, username="unknown"):
        """Create Computer nodes and their relationships (only for computers with IP addresses or open ports)"""
        computers_created = 0
        computers_skipped = 0
        
        for computer in computers:
            if not computer['sid'] or not computer['computer_name']:
                continue
            
            # Get IP addresses from DNS records if available
            ip_addresses = dns_records.get(computer['computer_name'], [])
            if isinstance(ip_addresses, str):
                ip_addresses = [ip_addresses]
            
            # Create node properties - ONLY ip_addresses and open_ports as requested
            properties = {
                "ip_addresses": ip_addresses if ip_addresses else [],
                "open_ports": []  # Will be updated below if port scan results exist
            }
            
            if ip_addresses:
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
                    unique_ports = sorted(list(set(all_open_ports)))
                    properties["open_ports"] = unique_ports
                    logger.debug(f"Added {len(unique_ports)} open ports for {computer['computer_name']}: {unique_ports}")
                else:
                    properties["open_ports"] = []
                    logger.debug(f"No open ports found for {computer['computer_name']}")
            else:
                logger.debug(f"No port scan results for {computer['computer_name']}")
            
            # SMB validation results removed - only keeping ip_addresses and open_ports
            
            # Skip computers with no IP addresses and no open ports (not useful in output)
            if not ip_addresses and not properties["open_ports"]:
                logger.debug(f"⚠️  Skipping Computer {computer['computer_name']} - no IP addresses or open ports")
                computers_skipped += 1
                continue
            
            # Create Website nodes and relationships (avoid duplicates per computer)
            if http_validation_results and port_scan_results and computer['computer_name'] in port_scan_results:
                unique_websites = {}  # Track unique websites per computer
                computer_ports = port_scan_results[computer['computer_name']]
                
                # Collect all unique websites from all IPs
                for ip in ip_addresses:
                    if ip in computer_ports:
                        for port in computer_ports[ip]:
                            target = f"{ip}:{port}"
                            if target in http_validation_results:
                                http_result = http_validation_results[target]
                                
                                # Check HTTP
                                if http_result['http']['status']:
                                    website_key = f"http-{port}"  # Unique key per protocol+port
                                    if website_key not in unique_websites:
                                        unique_websites[website_key] = {
                                            'ip': ip,
                                            'port': port,
                                            'protocol': 'http',
                                            'result': http_result
                                        }
                                
                                # Check HTTPS
                                if http_result['https']['status']:
                                    website_key = f"https-{port}"  # Unique key per protocol+port
                                    if website_key not in unique_websites:
                                        unique_websites[website_key] = {
                                            'ip': ip,
                                            'port': port,
                                            'protocol': 'https',
                                            'result': http_result
                                        }
                
                # Create unique Website nodes
                for website_key, website_info in unique_websites.items():
                    website_node_id = self.create_website_node(
                        website_info['ip'], 
                        website_info['port'], 
                        website_info['result'], 
                        website_info['protocol']
                    )
                    
                    # Create edge from computer to website
                    self.builder.create_edge(
                        start_value=computer['sid'],
                        end_value=website_node_id,
                        kind="ExposeInterface"
                    )
            
            # Create computer node
            self.builder.create_node(
                id=computer['sid'],
                kinds=["Computer"],
                properties=properties
            )
            computers_created += 1
            
            # Create edges from computer to subnets for each IP
            if ip_addresses and subnets:
                self.create_computer_subnet_edges(computer, ip_addresses, subnets)
            
            # Create FileShare nodes and relationships (only if SMB validation found shares)
            self.create_fileshare_nodes_from_smb_validation(computer, ip_addresses, smb_validation_results, username)
        
        # Log summary
        logger.info(f"✅ Created {computers_created} Computer nodes (computers with IP addresses or open ports)")
        if computers_skipped > 0:
            logger.info(f"⚠️  Skipped {computers_skipped} computers (no IP addresses or open ports - not useful in output)")
    
    def create_computer_subnet_edges(self, computer, ip_addresses, subnets):
        """Create edges from computer to subnets"""
        created_edges = set()  # Avoid duplicate edges to same subnet
        
        for subnet_str, subnet_info in subnets.items():
            for host in subnet_info['hosts']:
                if host['hostname'] == computer['computer_name']:
                    subnet_id = self.subnet_ids[subnet_str]
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
                        
                        self.builder.create_edge(
                            start_value=computer['sid'],
                            end_value=subnet_id,
                            kind="LocatedIn"
                        )
                        created_edges.add(subnet_id)
                        logger.debug(f"Created edge: {computer['computer_name']} -> {subnet_str} (IPs: {subnet_ips})")
                    break
    
    def create_fileshare_nodes_from_smb_validation(self, computer, ip_addresses, smb_validation_results, username="unknown"):
        """Create FileShare nodes based on SMB validation results using SMB Shares Manager"""
        from validators.smb_shares_manager import SMBSharesManager
        
        if not smb_validation_results:
            return
        
        # Use the consolidated SMB shares manager
        manager = SMBSharesManager()
        fileshare_nodes, fileshare_edges = manager.create_fileshare_nodes_for_computer(
            computer, ip_addresses, smb_validation_results, username
        )
        
        # Add the nodes and edges to the builder
        for node in fileshare_nodes:
            self.builder.create_node(
                id=node['id'],
                kinds=node['kinds'],
                properties=node['properties']
            )
        
        for edge in fileshare_edges:
            self.builder.create_edge(
                start_value=edge['start']['value'],
                end_value=edge['end']['value'],
                kind=edge['kind'],
                properties=edge.get('properties', {})
            )
    
    def create_device_nodes(self, shadow_devices, port_scan_results=None, http_validation_results=None, smb_validation_results=None, username="unknown"):
        """Create Device nodes for shadow-IT devices"""
        if not shadow_devices:
            return
        
        logger.info(f"Creating Device nodes for {len(shadow_devices)} shadow-IT devices...")
        
        devices_created = 0
        devices_skipped = 0
        
        for device_id, device_info in shadow_devices.items():
            device_ip = device_info['ip']
            
            # Check if device has open ports
            has_open_ports = False
            all_open_ports = []
            
            if port_scan_results and device_info['device_name'] in port_scan_results:
                device_ports = port_scan_results[device_info['device_name']]
                for ip, ports in device_ports.items():
                    if ports:  # If there are any open ports
                        has_open_ports = True
                        for port in ports:
                            all_open_ports.append(port)
            
            # Only create Device node if it has open ports (confirmed reachable)
            if not has_open_ports:
                logger.debug(f"Skipping Device {device_info['ip']} - no open ports found (device not reachable)")
                devices_skipped += 1
                continue
            
            devices_created += 1
            
            device_properties = {
                "name": device_info['device_name'],
                "ip_address": device_ip,
                "device_type": device_info['device_type'],
                "is_shadow_it": device_info['is_shadow_it'],
                "site": device_info['site']
            }
            
            # Add port scan results
            if all_open_ports:
                unique_ports = sorted(list(set(all_open_ports)))
                device_properties["open_ports"] = unique_ports
            
            # Create Device node
            self.builder.create_node(
                id=device_id,
                kinds=["Device"],
                properties=device_properties
            )
            
            # Create Device → Website relationships (if HTTP validation results exist)
            if http_validation_results:
                self.create_device_website_relationships(device_id, device_ip, http_validation_results)
            
            # Create Device → FileShare relationships (if SMB validation results exist)
            if smb_validation_results:
                # Create a pseudo-computer object for FileShare creation
                pseudo_computer = {
                    'sid': device_id,
                    'computer_name': device_info['device_name']
                }
                device_ips = [device_ip]
                self.create_fileshare_nodes_from_smb_validation(pseudo_computer, device_ips, smb_validation_results, username)
            
            # Create edge from device to subnet
            self.create_device_subnet_edge(device_id, device_info)
            
            logger.debug(f"Created Device node: {device_info['ip']} (Shadow-IT)")
        
        # Log summary
        logger.info(f"✅ Created {devices_created} Device nodes (devices with open ports)")
        if devices_skipped > 0:
            logger.info(f"⚠️  Skipped {devices_skipped} devices (no open ports - not reachable)")
    
    def create_device_website_relationships(self, device_id, device_ip, http_validation_results):
        """Create Website relationships for shadow-IT devices"""
        for target, http_result in http_validation_results.items():
            target_ip, target_port = target.split(':')
            if target_ip == device_ip:
                # Create Website node for HTTP
                if http_result['http']['status']:
                    website_node_id = self.create_website_node(device_ip, target_port, http_result, 'http')
                    
                    # Create Device → Website edge
                    self.builder.create_edge(
                        start_value=device_id,
                        end_value=website_node_id,
                        kind="ExposeInterface"
                    )
                
                # Create Website node for HTTPS
                if http_result['https']['status']:
                    website_node_id = self.create_website_node(device_ip, target_port, http_result, 'https')
                    
                    # Create Device → Website edge
                    self.builder.create_edge(
                        start_value=device_id,
                        end_value=website_node_id,
                        kind="ExposeInterface"
                    )
    
    def create_device_subnet_edge(self, device_id, device_info):
        """Create edge from device to subnet"""
        device_subnet = device_info['subnet']
        for subnet_str in self.subnet_ids:
            if subnet_str == device_subnet:
                subnet_id = self.subnet_ids[subnet_str]
                self.builder.create_edge(
                    start_value=device_id,
                    end_value=subnet_id,
                    kind="LocatedIn"
                )
                break
    
    def build_topology(self, ad_client, computers, dns_records, port_scan_results=None, http_validation_results=None, smb_validation_results=None, shadow_devices=None, username="unknown"):
        """Build complete network topology"""
        # Get domain information first
        domain_info = ad_client.get_domain_info()
        
        # Store domain info in the builder for inclusion in JSON output
        if domain_info:
            self.builder.domain_info = domain_info
            logger.info(f"🏢 Domain: {domain_info['domain_name']} (SID: {domain_info['domain_sid']})")
        
        # Connect to existing Domain node
        self.connect_to_existing_domain(domain_info)
        
        # Query AD Sites and Services for configured subnets
        ad_subnets = ad_client.query_subnets()
        
        # Match resolved IPs to AD subnets
        subnets = match_ips_to_subnets(ad_subnets, dns_records)
        
        # Create all nodes and relationships
        self.create_site_nodes(subnets)
        self.create_subnet_nodes(subnets)
        self.create_computer_nodes(computers, dns_records, port_scan_results, http_validation_results, smb_validation_results, subnets, username)
        self.create_device_nodes(shadow_devices, port_scan_results, http_validation_results, smb_validation_results, username)
        
        return self.builder
    
    def save_to_file(self, output_file):
        """Save data to JSON file with domain info"""
        try:
            # Get the JSON data from the builder
            json_data = self.builder.to_json()
            
            # Parse the JSON and add domain_info if available
            import json
            data = json.loads(json_data)
            
            # Add domain_info if it exists in the builder
            if hasattr(self.builder, 'domain_info') and self.builder.domain_info:
                data['domain_info'] = self.builder.domain_info
                logger.debug(f"Added domain_info to JSON: {self.builder.domain_info['domain_name']} (SID: {self.builder.domain_info['domain_sid']})")
            
            # Save the modified JSON
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"OpenGraph JSON saved to: {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving JSON file: {e}")
            # Fallback to original method
            try:
                self.builder.save_to_file(output_file)
                return True
            except:
                return False
