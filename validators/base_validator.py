#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
Base Validator Class
Template for creating new protocol validators
"""

import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('NetworkHound.BaseValidator')

class BaseValidator(ABC):
    """Abstract base class for protocol validators"""
    
    def __init__(self, timeout=5, max_threads=10, use_multiprocessing=False):
        self.timeout = timeout
        self.max_threads = max_threads
        # Multiprocessing disabled - always use threading for stability
        self.use_multiprocessing = False
        self.protocol_name = self.__class__.__name__.replace('Validator', '').upper()
    
    @abstractmethod
    def validate_single_target(self, ip, port, **kwargs):
        """
        Validate a single IP:port combination
        
        Args:
            ip: Target IP address
            port: Target port
            **kwargs: Additional protocol-specific parameters
            
        Returns:
            dict: Validation results with standard format:
            {
                'protocol_name': {
                    'status': bool,
                    'error': str,
                    # ... protocol-specific fields
                }
            }
        """
        pass
    
    @abstractmethod
    def get_default_ports(self):
        """
        Return list of default ports for this protocol
        
        Returns:
            list: List of default port numbers
        """
        pass
    
    def validate_targets_threaded(self, ip_port_list, **kwargs):
        """
        Validate multiple IP:port combinations using threading/multiprocessing
        
        Args:
            ip_port_list: List of (ip, port) tuples
            **kwargs: Additional protocol-specific parameters
            
        Returns:
            dict: Results keyed by "ip:port" strings
        """
        if not ip_port_list:
            return {}
        
        # Filter only relevant ports if the validator defines specific ports
        relevant_ports = self.get_default_ports()
        if relevant_ports:
            ip_port_list = [(ip, port) for ip, port in ip_port_list if port in relevant_ports]
        
        if not ip_port_list:
            logger.info(f"No {self.protocol_name} ports found for validation")
            return {}
        
        logger.info(f"Starting {self.protocol_name} validation for {len(ip_port_list)} targets...")
        logger.info(f"Threads: {self.max_threads}, Timeout: {self.timeout}s")
        
        results = {}
        
        # Always use threading (multiprocessing disabled for stability)
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all validation tasks
            future_to_target = {
                executor.submit(self.validate_single_target, ip, port, **kwargs): f"{ip}:{port}"
                for ip, port in ip_port_list
            }
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1
                
                try:
                    result = future.result()
                    results[target] = result
                    self._log_result(target, result, completed, len(ip_port_list))
                except Exception as e:
                    results[target] = self._create_error_result(str(e))
                    logger.debug(f"[{completed}/{len(ip_port_list)}] {target}: Validation error - {e}")
        
        # Summary
        successful = sum(1 for r in results.values() 
                        if r.get(self.protocol_name.lower(), {}).get('status', False))
        logger.info(f"{self.protocol_name} validation results: {successful}/{len(ip_port_list)} successful")
        
        return results
    
    def _worker_process(self, args):
        """Worker function for multiprocessing"""
        ip, port, timeout, kwargs = args
        
        # Create a temporary validator instance for this process
        temp_validator = self.__class__(timeout=timeout, use_multiprocessing=False)
        return temp_validator.validate_single_target(ip, port, **kwargs)
    
    def _create_error_result(self, error_message):
        """Create a standard error result"""
        return {
            self.protocol_name.lower(): {
                'status': False,
                'error': error_message[:100]  # Limit error length
            }
        }
    
    def _log_result(self, target, result, completed, total):
        """Log validation result - can be overridden by subclasses"""
        protocol_result = result.get(self.protocol_name.lower(), {})
        status = "✅" if protocol_result.get('status', False) else "❌"
        error = protocol_result.get('error', '')
        error_str = f" - {error}" if error else ""
        
        logger.debug(f"[{completed}/{total}] {target}: {status}{self.protocol_name}{error_str}")
    
    @classmethod
    def get_validator_info(cls):
        """Get information about this validator"""
        return {
            'name': cls.__name__,
            'protocol': cls.__name__.replace('Validator', '').upper(),
            'description': cls.__doc__ or f"{cls.__name__} protocol validator",
            'default_ports': cls().get_default_ports() if hasattr(cls, 'get_default_ports') else []
        }


# Example template for creating new validators
class TemplateValidator(BaseValidator):
    """
    Template for creating new protocol validators
    Copy this class and modify for new protocols
    """
    
    def validate_single_target(self, ip, port, **kwargs):
        """Validate a single target for TEMPLATE protocol"""
        results = {
            'template': {
                'status': False,
                'error': None,
                'version': None,
                'service_info': None
                # Add more protocol-specific fields here
            }
        }
        
        try:
            # TODO: Implement actual protocol validation logic here
            # Example:
            # connection = create_connection(ip, port, self.timeout)
            # service_info = get_service_info(connection)
            # results['template']['status'] = True
            # results['template']['version'] = service_info.get('version')
            # results['template']['service_info'] = service_info
            
            pass  # Remove this when implementing
            
        except Exception as e:
            results['template']['error'] = str(e)[:100]
            logger.debug(f"TEMPLATE validation failed for {ip}:{port}: {e}")
        
        return results
    
    def get_default_ports(self):
        """Return default ports for TEMPLATE protocol"""
        return [1234, 5678]  # TODO: Replace with actual protocol ports


