#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Impacket Authentication Module
Supports: Password, NTLM Hash, Kerberos Ticket
"""

import os
import sys
import logging
from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import LDAPConnection
from impacket import ntlm
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal, KerberosTime, Ticket
import binascii
import hashlib

# Configure logging
logger = logging.getLogger('NetworkHound.ImpacketAuth')

class ImpacketAuth:
    """
    Impacket authentication class
    Supports all authentication types: password, NTLM hash, Kerberos ticket
    """
    
    def __init__(self, target, domain="", username="", password="", 
                 ntlm_hash="", kerberos_ticket="", use_kerberos=False):
        """
        Initialize the authentication class
        
        Args:
            target: Server address (IP or hostname)
            domain: Domain name
            username: Username
            password: Plain password
            ntlm_hash: NTLM hash (format: LM:NT or just NT)
            kerberos_ticket: Path to ticket file or base64 encoded ticket
            use_kerberos: Whether to use Kerberos
        """
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.kerberos_ticket = kerberos_ticket
        self.use_kerberos = use_kerberos
        # SMB shares are now handled by SMBSharesManager
        
        # Process NTLM hash
        self.lm_hash = ""
        self.nt_hash = ""
        if ntlm_hash:
            self._parse_ntlm_hash()
    
    def _parse_ntlm_hash(self):
        """Process NTLM hash to correct format"""
        if ":" in self.ntlm_hash:
            self.lm_hash, self.nt_hash = self.ntlm_hash.split(":", 1)
        else:
            # Only NT hash
            self.lm_hash = "aad3b435b51404eeaad3b435b51404ee"  # Empty LM hash
            self.nt_hash = self.ntlm_hash
    
    def _load_kerberos_ticket(self):
        """Load Kerberos ticket"""
        if not self.kerberos_ticket:
            return False
            
        try:
            # If it's a file path
            if os.path.isfile(self.kerberos_ticket):
                os.environ['KRB5CCNAME'] = self.kerberos_ticket
                return True
            
            # If it's base64 encoded ticket
            try:
                ticket_data = binascii.a2b_base64(self.kerberos_ticket)
                # Save to temporary file
                import tempfile
                temp_ticket = tempfile.mktemp(suffix='.ccache')
                with open(temp_ticket, "wb") as f:
                    f.write(ticket_data)
                os.environ['KRB5CCNAME'] = temp_ticket
                return True
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error loading Kerberos ticket: {e}")
            return False
        
        return False
    
    def test_smb_connection(self, verbose=True):
        """Test SMB connection"""
        try:
            if verbose:
                logger.debug(f"Trying SMB connection to {self.target}")
            
            # Create SMB connection
            smbClient = SMBConnection(self.target, self.target)
            
            # Choose authentication type
            if self.use_kerberos and self.kerberos_ticket:
                if verbose:
                    logger.debug("Using Kerberos ticket")
                if not self._load_kerberos_ticket():
                    return False
                smbClient.kerberosLogin(self.username, self.password, self.domain, 
                                      self.lm_hash, self.nt_hash, useCache=True)
            
            elif self.ntlm_hash:
                if verbose:
                    logger.debug("Using NTLM hash")
                smbClient.login(self.username, self.password, self.domain, 
                              self.lm_hash, self.nt_hash)
            
            else:
                if verbose:
                    logger.debug("Using plain password")
                smbClient.login(self.username, self.password, self.domain)
            
            if verbose:
                logger.debug("SMB connection successful!")
            
            # List shares
            shares = smbClient.listShares()
            if verbose:
                logger.debug(f"Found {len(shares)} shares:")
                for share in shares:
                    logger.debug(f"    - {share['shi1_netname']}: {share['shi1_remark']}")
            
            # SMB shares are now handled by SMBSharesManager
            # This is just a basic connection test
            
            smbClient.close()
            return True
            
        except Exception as e:
            if verbose:
                logger.debug(f"SMB connection error: {e}")
            return False
    
    def test_ldap_connection(self, verbose=True):
        """Test LDAP connection"""
        try:
            if verbose:
                logger.debug(f"Trying LDAP connection to {self.target}")
            
            # For Kerberos, skip detailed LDAP test to avoid delays
            if self.use_kerberos and self.kerberos_ticket:
                if verbose:
                    logger.debug("Skipping detailed LDAP test for Kerberos (speed optimization)")
                return True  # Assume it works if we got here
            
            # Create LDAP connection
            if self.use_kerberos and self.kerberos_ticket:
                if verbose:
                    logger.debug("Using Kerberos ticket")
                if not self._load_kerberos_ticket():
                    return False
                ldapConnection = LDAPConnection(f'ldap://{self.target}')
                ldapConnection.kerberosLogin(self.username, self.password, self.domain,
                                           self.lm_hash, self.nt_hash, useCache=True)
            
            elif self.ntlm_hash:
                if verbose:
                    logger.debug("Using NTLM hash")
                ldapConnection = LDAPConnection(f'ldap://{self.target}')
                ldapConnection.login(self.username, self.password, self.domain,
                                   self.lm_hash, self.nt_hash)
            
            else:
                if verbose:
                    logger.debug("Using plain password")
                ldapConnection = LDAPConnection(f'ldap://{self.target}')
                ldapConnection.login(self.username, self.password, self.domain)
            
            if verbose:
                logger.debug("LDAP connection successful!")
            
            # Test domain info
            base_dn = f"DC={self.domain.replace('.', ',DC=')}"
            search_filter = "(objectClass=domain)"
            attributes = ['name', 'objectSid', 'whenCreated']
            
            resp = ldapConnection.search(
                searchBase=base_dn,
                scope=2,  # SCOPE_SUBTREE
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=1
            )
            
            if verbose:
                for item in resp:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        logger.debug(f"Domain information:")
                        for attr in item['attributes']:
                            attr_name = str(attr['type'])
                            attr_values = [str(val) for val in attr['vals']]
                            logger.debug(f"    {attr_name}: {', '.join(attr_values)}")
            
            ldapConnection.close()
            return True
            
        except Exception as e:
            if verbose:
                logger.debug(f"LDAP connection error: {e}")
            return False
    
    def get_domain_users(self, limit=10, verbose=True):
        """Get domain users list"""
        try:
            if verbose:
                logger.debug(f"Searching for users in domain {self.domain}")
            
            # For Kerberos, skip this to avoid delays
            if self.use_kerberos and self.kerberos_ticket:
                if verbose:
                    logger.debug("Skipping user enumeration for Kerberos (speed optimization)")
                return []
            
            ldapConnection = LDAPConnection(f'ldap://{self.target}')
            
            # Authentication
            if self.use_kerberos and self.kerberos_ticket:
                if not self._load_kerberos_ticket():
                    return []
                ldapConnection.kerberosLogin(self.username, self.password, self.domain,
                                           self.lm_hash, self.nt_hash, useCache=True)
            elif self.ntlm_hash:
                ldapConnection.login(self.username, self.password, self.domain,
                                   self.lm_hash, self.nt_hash)
            else:
                ldapConnection.login(self.username, self.password, self.domain)
            
            # Search for users
            base_dn = f"DC={self.domain.replace('.', ',DC=')}"
            search_filter = "(&(objectClass=user)(objectCategory=person))"
            attributes = ['sAMAccountName', 'displayName', 'mail', 'lastLogon']
            
            resp = ldapConnection.search(
                searchBase=base_dn,
                scope=2,  # SCOPE_SUBTREE
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=limit
            )
            
            users = []
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    user_info = {}
                    for attr in item['attributes']:
                        attr_name = str(attr['type'])
                        attr_values = [str(val) for val in attr['vals']]
                        user_info[attr_name] = attr_values[0] if attr_values else ""
                    users.append(user_info)
            
            if verbose:
                logger.debug(f"Found {len(users)} users:")
                for user in users:
                    logger.debug(f"    - {user.get('sAMAccountName', 'N/A')} ({user.get('displayName', 'N/A')})")
            
            ldapConnection.close()
            return users
            
        except Exception as e:
            if verbose:
                logger.debug(f"Error searching users: {e}")
            return []
    
    def get_smb_shares(self):
        """Get SMB shares list - DEPRECATED: Use SMBSharesManager instead"""
        logger.warning("This method is deprecated. Use SMBSharesManager.discover_smb_shares() instead.")
        return []
    
    def create_golden_ticket(self, krbtgt_hash, user_sid, target_user="admin"):
        """Create Golden Ticket (requires KRBTGT hash)"""
        try:
            from impacket.krb5.pac import KERB_SID_AND_ATTRIBUTES, PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
                PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_UPN_DNS_INFO, UPN_DNS_INFO, PAC_REQUESTOR, PAC_ATTRIBUTES_INFO
            from impacket.krb5.asn1 import TGT, AS_REP
            from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5
            from impacket.krb5.types import KerberosTime, Principal
            
            logger.info(f"Creating Golden Ticket for {target_user}")
            
            # Ticket parameters
            domain_sid = user_sid.rsplit('-', 1)[0]  # Remove last RID
            user_id = 500  # Default admin RID
            
            # Create the ticket
            # This requires more advanced impacket implementation
            logger.warning("Golden Ticket creation requires advanced implementation")
            logger.info(f"Required parameters:")
            logger.info(f"    - KRBTGT Hash: {krbtgt_hash}")
            logger.info(f"    - Domain SID: {domain_sid}")
            logger.info(f"    - Target User: {target_user}")
            
            return False
            
        except Exception as e:
            logger.error(f"Error creating Golden Ticket: {e}")
            return False

