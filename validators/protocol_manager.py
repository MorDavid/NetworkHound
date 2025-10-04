#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
Protocol Manager
Centralized management for all protocol validators
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('NetworkHound.ProtocolManager')

class ProtocolManager:
    """Manages all protocol validators and their execution"""
    
    def __init__(self):
        self.validators = {}
        self._load_validators()
    
    def _load_validators(self):
        """Load all available validators"""
        try:
            # Try relative import first, then absolute
            try:
                from .http_validator import HTTPValidator
            except ImportError:
                from validators.http_validator import HTTPValidator
            self.validators['http'] = HTTPValidator
            logger.debug("Loaded HTTPValidator")
        except ImportError as e:
            logger.warning(f"Failed to load HTTPValidator: {e}")
        
        try:
            try:
                from .smb_shares_manager import SMBSharesManager
            except ImportError:
                from validators.smb_shares_manager import SMBSharesManager
            self.validators['smb'] = SMBSharesManager
            logger.debug("Loaded SMBSharesManager")
        except ImportError as e:
            logger.warning(f"Failed to load SMBSharesManager: {e}")
        
        # Add more validators here as they are created
        
        logger.info(f"Loaded {len(self.validators)} protocol validators: {list(self.validators.keys())}")
    
    def get_available_protocols(self) -> List[str]:
        """Get list of available protocol names"""
        return list(self.validators.keys())
    
    def get_validator(self, protocol: str, **kwargs):
        """Get a validator instance for a specific protocol"""
        if protocol not in self.validators:
            raise ValueError(f"Protocol '{protocol}' not available. Available: {list(self.validators.keys())}")
        
        return self.validators[protocol](**kwargs)
    
    def get_all_default_ports(self) -> Dict[str, List[int]]:
        """Get default ports for all protocols"""
        ports = {}
        for protocol, validator_class in self.validators.items():
            try:
                temp_validator = validator_class()
                if hasattr(temp_validator, 'get_default_ports'):
                    ports[protocol] = temp_validator.get_default_ports()
                else:
                    ports[protocol] = []
            except Exception as e:
                logger.warning(f"Failed to get default ports for {protocol}: {e}")
                ports[protocol] = []
        
        return ports
    
    def get_protocol_info(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed information about all protocols"""
        info = {}
        for protocol, validator_class in self.validators.items():
            try:
                temp_validator = validator_class()
                info[protocol] = {
                    'name': validator_class.__name__,
                    'description': validator_class.__doc__ or f"{protocol.upper()} protocol validator",
                    'default_ports': temp_validator.get_default_ports() if hasattr(temp_validator, 'get_default_ports') else [],
                    'class': validator_class.__name__
                }
            except Exception as e:
                logger.warning(f"Failed to get info for {protocol}: {e}")
                info[protocol] = {
                    'name': validator_class.__name__,
                    'description': f"Error loading {protocol}: {e}",
                    'default_ports': [],
                    'class': validator_class.__name__
                }
        
        return info
    
    def validate_protocols(self, protocols: List[str], port_scan_results: Dict, 
                          max_threads: int = 10, timeout: int = 5, **kwargs) -> Dict[str, Dict]:
        """
        Validate multiple protocols against port scan results
        
        Args:
            protocols: List of protocol names to validate
            port_scan_results: Results from port scanning
            max_threads: Maximum number of threads per validator
            timeout: Timeout per validation
            **kwargs: Additional protocol-specific arguments
            
        Returns:
            Dict mapping protocol names to their validation results
        """
        if not port_scan_results:
            return {}
        
        results = {}
        
        for protocol in protocols:
            if protocol not in self.validators:
                logger.warning(f"Protocol '{protocol}' not available, skipping")
                continue
            
            logger.info(f"🔍 Validating {protocol.upper()} protocol...")
            
            try:
                # Get validator instance
                validator = self.get_validator(protocol, timeout=timeout, max_threads=max_threads)
                
                # Collect relevant IP:port combinations
                ip_port_list = self._collect_targets_for_protocol(port_scan_results, validator)
                
                if not ip_port_list:
                    logger.info(f"No {protocol.upper()} ports found for validation")
                    results[protocol] = {}
                    continue
                
                # Perform validation
                if hasattr(validator, 'validate_targets_threaded'):
                    # Use the base validator method
                    validation_results = validator.validate_targets_threaded(ip_port_list, **kwargs)
                elif hasattr(validator, 'validate_smb_ports_threaded'):
                    # Special case for SMB manager
                    validation_results = validator.validate_smb_ports_threaded(
                        ip_port_list, 
                        kwargs.get('username', ''),
                        kwargs.get('password', ''),
                        kwargs.get('domain', ''),
                        kwargs.get('ntlm_hash', ''),
                        kwargs.get('kerberos_ticket', '')
                    )
                else:
                    logger.warning(f"Validator for {protocol} doesn't have a threaded validation method")
                    validation_results = {}
                
                results[protocol] = validation_results
                
            except Exception as e:
                logger.error(f"Failed to validate {protocol}: {e}")
                results[protocol] = {}
        
        return results
    
    def _collect_targets_for_protocol(self, port_scan_results: Dict, validator) -> List[tuple]:
        """Collect IP:port targets relevant for a specific validator"""
        targets = []
        
        # Get default ports for this validator
        if hasattr(validator, 'get_default_ports'):
            relevant_ports = validator.get_default_ports()
        else:
            # If no default ports defined, include all ports
            relevant_ports = None
        
        for computer_name, computer_ports in port_scan_results.items():
            for ip, ports in computer_ports.items():
                for port in ports:
                    if relevant_ports is None or port in relevant_ports:
                        targets.append((ip, port))
        
        return targets
    
    def print_protocol_summary(self):
        """Print a summary of all available protocols"""
        logger.info("\n🔍 Available Protocol Validators:")
        logger.info("=" * 50)
        
        info = self.get_protocol_info()
        for protocol, details in info.items():
            logger.info(f"\n📋 {protocol.upper()}")
            logger.info(f"   Class: {details['class']}")
            logger.info(f"   Ports: {details['default_ports']}")
            logger.info(f"   Description: {details['description']}")
        
        logger.info(f"\n✅ Total: {len(info)} protocol validators available")


# Global instance for easy access
protocol_manager = ProtocolManager()


