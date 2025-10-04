#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
Active Directory client for querying computers and subnets
"""

import ipaddress
import logging
from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPException
from utils.config import LDAP_COMPUTER_ATTRIBUTES, LDAP_SUBNET_ATTRIBUTES

# Configure logging
logger = logging.getLogger('NetworkHound.ADClient')


class ADClient:
    """Active Directory LDAP client"""
    
    def __init__(self, dc_host, domain, username, password):
        self.dc_host = dc_host
        self.domain = domain
        self.username = username
        self.password = password
        self.connection = None
    
    def connect(self):
        """Connect to Domain Controller using LDAP"""
        try:
            # Create server object
            server = Server(self.dc_host, get_info=ALL)
            
            # Create connection with NTLM authentication
            user_dn = f"{self.domain}\\{self.username}"
            self.connection = Connection(
                server, 
                user=user_dn, 
                password=self.password, 
                authentication=NTLM, 
                auto_bind=True
            )
            
            logger.info(f"Successfully connected to DC: {self.dc_host}")
            return True
            
        except LDAPException as e:
            logger.error(f"LDAP connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def disconnect(self):
        """Close LDAP connection"""
        if self.connection:
            self.connection.unbind()
            self.connection = None
    
    def query_computers(self):
        """Query all computer objects from Active Directory"""
        if not self.connection:
            raise Exception("Not connected to AD. Call connect() first.")
        
        try:
            # Convert domain to DN format (e.g., company.local -> DC=company,DC=local)
            domain_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
            
            # Search for computer objects
            search_base = domain_dn
            search_filter = '(objectClass=computer)'
            
            self.connection.search(search_base, search_filter, attributes=LDAP_COMPUTER_ATTRIBUTES)
            
            computers = []
            for entry in self.connection.entries:
                computer_info = {
                    'sid': str(entry.objectSid) if entry.objectSid else None,
                    'computer_name': str(entry.cn) if entry.cn else None,
                    'dns_hostname': str(entry.dNSHostName) if entry.dNSHostName else None,
                    'os': str(entry.operatingSystem) if entry.operatingSystem else None
                }
                computers.append(computer_info)
            
            logger.info(f"Found {len(computers)} computer objects")
            return computers
            
        except LDAPException as e:
            logger.error(f"LDAP query failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Query error: {e}")
            return []
    
    def query_subnets(self):
        """Query AD Sites and Services for configured subnets"""
        if not self.connection:
            logger.warning("No AD connection available - returning empty subnets")
            return {}
        
        try:
            # Check if this is an impacket connection (has query_ad_subnets method)
            if hasattr(self.connection, 'impacket_auth'):
                logger.debug("Using impacket connection for subnet query")
                # Import the query function from main_final
                import sys
                import importlib
                main_module = sys.modules.get('__main__')
                if main_module and hasattr(main_module, 'query_ad_subnets'):
                    return main_module.query_ad_subnets(self.connection, self.domain)
                else:
                    logger.warning("query_ad_subnets function not available")
                    return {}
            
            # Original ldap3 code for backward compatibility
            # Convert domain to DN format - handle None domain
            if not self.domain:
                logger.warning("No domain specified - cannot query AD subnets")
                return {}
                
            domain_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
            
            # Search for subnet objects in AD Sites and Services
            search_base = f"CN=Subnets,CN=Sites,CN=Configuration,{domain_dn}"
            search_filter = '(objectClass=subnet)'
            
            self.connection.search(search_base, search_filter, attributes=LDAP_SUBNET_ATTRIBUTES)
            
            ad_subnets = {}
            for entry in self.connection.entries:
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
            
            return ad_subnets
            
        except LDAPException as e:
            logger.error(f"AD subnet query failed: {e}")
            return {}
        except Exception as e:
            logger.error(f"AD subnet query error: {e}")
            return {}
    
    def get_domain_info(self):
        """Get domain information including SID"""
        if not self.connection:
            logger.warning("No AD connection available - manual mode")
            # Return minimal domain info for manual mode
            return {
                'domain_name': self.domain or 'manual.local',
                'domain_sid': None,  # No real domain SID in manual mode
                'distinguished_name': ','.join([f"DC={part}" for part in (self.domain or 'manual.local').split('.')]),
                'description': 'Manual network scanning mode'
            }
        
        try:
            # Check if this is an impacket connection
            if hasattr(self.connection, 'impacket_auth'):
                logger.debug("Using impacket connection for domain info query")
                
                # Convert domain to DN format
                domain_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
                
                # Search for domain object using impacket
                search_base = domain_dn
                search_filter = '(objectClass=domain)'
                
                results = self.connection.search(search_base, search_filter, attributes=['objectSid', 'name', 'description'])
                
                # Use connection.entries like in NetworkHound.py
                if hasattr(self.connection, 'entries') and self.connection.entries:
                    entry = self.connection.entries[0]
                    
                    # Always use computer SID method for reliable domain SID extraction
                    # Direct domain SID parsing from domain object is unreliable with impacket
                    domain_sid = self._get_domain_sid_from_computer()
                    
                    # If computer method fails, try direct parsing as fallback
                    if not domain_sid or not domain_sid.startswith('S-1-5-21-'):
                        logger.debug("Computer SID method failed, trying direct domain SID parsing")
                        raw_domain_sid = getattr(entry, 'objectSid', None)
                        
                        if raw_domain_sid and hasattr(self.connection, '_parse_binary_sid'):
                            try:
                                if isinstance(raw_domain_sid, str) and len(raw_domain_sid) >= 12:
                                    sid_bytes = raw_domain_sid.encode('latin1')
                                    domain_sid = self.connection._parse_binary_sid(sid_bytes)
                                elif isinstance(raw_domain_sid, bytes) and len(raw_domain_sid) >= 12:
                                    domain_sid = self.connection._parse_binary_sid(raw_domain_sid)
                                else:
                                    domain_sid = str(raw_domain_sid)
                            except Exception as e:
                                logger.debug(f"Failed to parse domain SID: {e}")
                                domain_sid = None  # Failed to parse
                        else:
                            domain_sid = None  # Failed to get domain SID
                    
                    # Critical check: If we still don't have a domain SID, this is a fatal error
                    if not domain_sid or not domain_sid.startswith('S-1-5-21-'):
                        logger.error("❌ CRITICAL ERROR: Could not extract domain SID from Active Directory")
                        logger.error("   This is required for proper BloodHound analysis")
                        logger.error("   Possible causes:")
                        logger.error("   • Insufficient privileges to read domain objects")
                        logger.error("   • Clock skew issues with Kerberos authentication")
                        logger.error("   • Network connectivity problems")
                        logger.error("   • Domain controller not responding properly")
                        logger.error("")
                        logger.error("💡 Troubleshooting steps:")
                        logger.error("   1. Verify credentials: Try with Domain Admin account")
                        logger.error("   2. Check Kerberos: Run 'klist -c $KRB5CCNAME' to verify ticket")
                        logger.error("   3. Test connectivity: ping DC and check port 389/636")
                        logger.error("   4. Try different auth: Use password instead of Kerberos")
                        logger.error("   5. Check domain name: Ensure correct FQDN")
                        raise Exception("Failed to extract domain SID - cannot continue with AD analysis")
                    
                    domain_info = {
                        'domain_name': self.domain,
                        'domain_sid': str(domain_sid) if domain_sid else None,
                        'distinguished_name': domain_dn,
                        'description': getattr(entry, 'description', '') or ''
                    }
                    logger.debug(f"Found domain: {self.domain} with SID: {domain_info['domain_sid']}")
                    return domain_info
                else:
                    # No domain object found - try to get domain SID from computer objects
                    logger.warning("No domain object found in AD - trying computer objects")
                    domain_sid = self._get_domain_sid_from_computer()
                    
                    # Critical check: If we can't get domain SID from computers either
                    if not domain_sid or not domain_sid.startswith('S-1-5-21-'):
                        logger.error("❌ CRITICAL ERROR: No domain object found and no computer SIDs available")
                        logger.error("   Cannot extract domain SID from Active Directory")
                        logger.error("   Possible causes:")
                        logger.error("   • No computer objects in domain (empty domain)")
                        logger.error("   • Insufficient privileges to read domain/computer objects")
                        logger.error("   • Authentication failure")
                        logger.error("   • Wrong domain specified")
                        logger.error("")
                        logger.error("💡 Troubleshooting steps:")
                        logger.error("   1. Verify domain name: Check FQDN is correct")
                        logger.error("   2. Test basic LDAP: ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=local'")
                        logger.error("   3. Check permissions: Try with higher privileged account")
                        logger.error("   4. Verify domain has computers: Check AD Users and Computers")
                        logger.error("   5. Try manual mode: Use --networks instead of --dc")
                        raise Exception("No domain information available - cannot continue with AD analysis")
                    
                    return {
                        'domain_name': self.domain,
                        'domain_sid': domain_sid,
                        'distinguished_name': domain_dn,
                        'description': 'Domain (via computer objects)'
                    }
            
            # Original ldap3 code for backward compatibility
            # Convert domain to DN format
            domain_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
            
            # Search for domain object
            search_base = domain_dn
            search_filter = '(objectClass=domain)'
            
            self.connection.search(search_base, search_filter, attributes=['objectSid', 'name', 'description'])
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                # Convert binary SID to proper string format
                domain_sid = None
                if entry.objectSid:
                    try:
                        # Use the same SID parsing logic as in main_final.py
                        if hasattr(self.connection, '_parse_binary_sid'):
                            # If using ImpacketLDAPWrapper
                            if isinstance(str(entry.objectSid), str) and len(str(entry.objectSid)) >= 12:
                                sid_bytes = str(entry.objectSid).encode('latin1')
                                domain_sid = self.connection._parse_binary_sid(sid_bytes)
                            else:
                                domain_sid = str(entry.objectSid)
                        else:
                            # Fallback for regular ldap3
                            domain_sid = str(entry.objectSid)
                    except Exception as e:
                        logger.debug(f"Failed to convert domain SID: {e}")
                        domain_sid = str(entry.objectSid)
                
                domain_info = {
                    'domain_name': self.domain,
                    'domain_sid': domain_sid,
                    'distinguished_name': domain_dn,
                    'description': str(entry.description) if entry.description else ''
                }
                logger.debug(f"Found domain: {self.domain} with SID: {domain_info['domain_sid']}")
                return domain_info
            else:
                logger.warning("No domain object found")
                return None
                
        except Exception as e:
            logger.error(f"Error querying domain info: {e}")
            # Generate default domain info on error
            domain_sid = None  # Failed to extract domain SID
            return {
                'domain_name': self.domain or 'unknown.local',
                'domain_sid': domain_sid,
                'distinguished_name': ','.join([f"DC={part}" for part in (self.domain or 'unknown.local').split('.')]),
                'description': 'Domain (error fallback)'
            }
    
    def _get_domain_sid_from_computer(self):
        """Extract domain SID from a computer object SID"""
        try:
            if not hasattr(self.connection, 'impacket_auth'):
                return None
            
            # Query computer objects to get their SIDs
            domain_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
            search_base = domain_dn
            search_filter = '(objectClass=computer)'
            
            results = self.connection.search(search_base, search_filter, attributes=['objectSid'])
            logger.debug(f"Computer search returned {len(results) if results else 0} results")
            
            # Use connection.entries like in NetworkHound.py
            if hasattr(self.connection, 'entries') and self.connection.entries:
                logger.debug(f"Found {len(self.connection.entries)} computer entries")
                for entry in self.connection.entries:
                    computer_sid = getattr(entry, 'objectSid', None)
                    logger.debug(f"Computer SID raw: {computer_sid} (type: {type(computer_sid)})")
                    if computer_sid:
                        # Check if SID is already parsed as string (like in NetworkHound.py)
                        if isinstance(computer_sid, str) and computer_sid.startswith('S-1-5-21-'):
                            # SID is already parsed - extract domain part directly
                            sid_parts = computer_sid.split('-')
                            if len(sid_parts) >= 7:  # S-1-5-21-xxx-xxx-xxx-RID
                                # Domain SID is everything except the last part (RID)
                                domain_sid = '-'.join(sid_parts[:-1])
                                logger.debug(f"Extracted domain SID from computer: {domain_sid}")
                                return domain_sid
                        else:
                            # Try to parse binary SID if needed
                            if hasattr(self.connection, '_parse_binary_sid'):
                                try:
                                    if isinstance(computer_sid, str) and len(computer_sid) >= 12:
                                        sid_bytes = computer_sid.encode('latin1')
                                        parsed_sid = self.connection._parse_binary_sid(sid_bytes)
                                    elif isinstance(computer_sid, bytes) and len(computer_sid) >= 12:
                                        parsed_sid = self.connection._parse_binary_sid(computer_sid)
                                    else:
                                        parsed_sid = str(computer_sid)
                                    
                                    logger.debug(f"Parsed SID: {parsed_sid}")
                                    
                                    # Extract domain part from computer SID (remove last RID)
                                    # Computer SID format: S-1-5-21-domain-domain-domain-RID
                                    if parsed_sid and parsed_sid.startswith('S-1-5-21-'):
                                        sid_parts = parsed_sid.split('-')
                                        if len(sid_parts) >= 7:  # S-1-5-21-xxx-xxx-xxx-RID
                                            # Domain SID is everything except the last part (RID)
                                            domain_sid = '-'.join(sid_parts[:-1])
                                            logger.debug(f"Extracted domain SID from computer: {domain_sid}")
                                            return domain_sid
                                except Exception as e:
                                    logger.debug(f"Failed to parse computer SID: {e}")
                                    continue
            
            # No valid computer SID found - return None to indicate failure
            logger.warning("Could not extract domain SID from any computer object")
            return None
            
        except Exception as e:
            logger.debug(f"Error extracting domain SID from computer: {e}")
            return None
    
    def __enter__(self):
        """Context manager entry"""
        if self.connect():
            return self
        else:
            raise Exception("Failed to connect to Active Directory")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
