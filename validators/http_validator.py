#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-

"""
HTTP/HTTPS validation utilities
"""

import re
import ssl
import socket
import requests
import urllib3
import hashlib
import base64
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from utils.config import MAX_TITLE_LENGTH, MAX_ERROR_LENGTH, MAX_BODY_SIZE

# Configure logging
logger = logging.getLogger('NetworkHound.HTTPValidator')

# Try to import cryptography for advanced certificate parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Disable SSL warnings for HTTP checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_http_connectivity_worker(args):
    """Worker function for multiprocessing HTTP validation"""
    ip, port, timeout, detailed_ssl = args
    
    # Create a temporary HTTPValidator instance for this process
    validator = HTTPValidator(timeout=timeout, detailed_ssl=detailed_ssl, use_multiprocessing=False)
    return validator.test_http_connectivity(ip, port)


class HTTPValidator:
    """HTTP/HTTPS connectivity validator"""
    
    def __init__(self, timeout=5, max_threads=10, detailed_ssl=True, use_multiprocessing=True):
        self.timeout = timeout
        self.max_threads = max_threads
        self.detailed_ssl = detailed_ssl
        self.use_multiprocessing = use_multiprocessing
        self.max_processes = min(cpu_count(), max_threads // 2) if use_multiprocessing else 1
    
    def get_ssl_certificate_info(self, ip, port, detailed=True):
        """Get SSL certificate information
        
        Args:
            ip: Target IP address
            port: Target port
            detailed: If False, returns only basic SSL info for speed
        """
        ssl_info = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # Get certificate in DER format (this always works)
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Get cipher and protocol info
                    cipher_info = ssock.cipher()
                    protocol_version = ssock.version()
                    
                    # Parse certificate using cryptography library if available (only if detailed=True)
                    cert = None
                    if detailed and cert_der and HAS_CRYPTOGRAPHY:
                        try:
                            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                            cert = self._parse_x509_certificate(cert_obj)
                        except Exception as e:
                            ssl_info['parse_error'] = str(e)[:MAX_ERROR_LENGTH]
                    
                    # Always add basic connection info
                    if cipher_info:
                        ssl_info['cipher_suite'] = cipher_info[0] if len(cipher_info) > 0 else 'Unknown'
                        ssl_info['cipher_protocol'] = cipher_info[1] if len(cipher_info) > 1 else 'Unknown'
                        ssl_info['cipher_bits'] = cipher_info[2] if len(cipher_info) > 2 else 0
                    
                    ssl_info['protocol_version'] = protocol_version or 'Unknown'
                    
                    # Certificate fingerprints (only if detailed)
                    if detailed and cert_der:
                        ssl_info['sha1_fingerprint'] = hashlib.sha1(cert_der).hexdigest().upper()
                        ssl_info['sha256_fingerprint'] = hashlib.sha256(cert_der).hexdigest().upper()
                        ssl_info['md5_fingerprint'] = hashlib.md5(cert_der).hexdigest().upper()
                    
                    # Detailed certificate information (only if detailed=True)
                    if detailed and cert and not cert.get('error'):
                        # Basic certificate info - handle the tuple structure properly
                        try:
                            subject_list = cert.get('subject', [])
                            if subject_list:
                                ssl_info['subject'] = dict((x[0], x[1]) for x in subject_list if len(x) >= 2)
                            
                            issuer_list = cert.get('issuer', [])
                            if issuer_list:
                                ssl_info['issuer'] = dict((x[0], x[1]) for x in issuer_list if len(x) >= 2)
                        except Exception as e:
                            ssl_info['subject_parse_error'] = str(e)[:MAX_ERROR_LENGTH]
                        ssl_info['version'] = cert.get('version', 'Unknown')
                        ssl_info['serial_number'] = cert.get('serialNumber', 'Unknown')
                        
                        # Dates and validity
                        not_before = cert.get('notBefore')
                        not_after = cert.get('notAfter')
                        
                        if not_before:
                            ssl_info['valid_from'] = not_before
                            try:
                                start_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                                ssl_info['days_since_issued'] = (datetime.now() - start_date).days
                            except:
                                ssl_info['days_since_issued'] = None
                            
                        if not_after:
                            ssl_info['valid_until'] = not_after
                            # Check if certificate is expired
                            try:
                                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                ssl_info['is_expired'] = expiry_date < datetime.now()
                                ssl_info['days_until_expiry'] = (expiry_date - datetime.now()).days
                                
                                # Calculate validity period
                                if not_before:
                                    start_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                                    ssl_info['validity_period_days'] = (expiry_date - start_date).days
                            except:
                                ssl_info['is_expired'] = False
                                ssl_info['days_until_expiry'] = None
                                ssl_info['validity_period_days'] = None
                        
                        # Subject Alternative Names (enhanced)
                        san_list = []
                        san_types = {}
                        for ext in cert.get('subjectAltName', []):
                            san_list.append(f"{ext[0]}:{ext[1]}")
                            if ext[0] not in san_types:
                                san_types[ext[0]] = []
                            san_types[ext[0]].append(ext[1])
                        
                        ssl_info['subject_alt_names'] = san_list
                        ssl_info['san_dns_names'] = san_types.get('DNS', [])
                        ssl_info['san_ip_addresses'] = san_types.get('IP Address', [])
                        ssl_info['san_email_addresses'] = san_types.get('email', [])
                        
                        # Enhanced self-signed detection
                        subject_cn = ssl_info['subject'].get('commonName', '')
                        issuer_cn = ssl_info['issuer'].get('commonName', '')
                        subject_org = ssl_info['subject'].get('organizationName', '')
                        issuer_org = ssl_info['issuer'].get('organizationName', '')
                        
                        ssl_info['is_self_signed'] = (
                            subject_cn == issuer_cn and 
                            subject_org == issuer_org and
                            ssl_info['subject'] == ssl_info['issuer']
                        )
                        
                        # Certificate chain information
                        try:
                            peer_cert_chain = ssock.getpeercert_chain()
                            if peer_cert_chain:
                                ssl_info['certificate_chain_length'] = len(peer_cert_chain)
                                ssl_info['is_ca_certificate'] = len(peer_cert_chain) > 1
                            else:
                                ssl_info['certificate_chain_length'] = 1
                                ssl_info['is_ca_certificate'] = False
                        except:
                            ssl_info['certificate_chain_length'] = 1
                            ssl_info['is_ca_certificate'] = False
                        
                        # Cipher and protocol information
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            ssl_info['cipher_suite'] = cipher_info[0] if len(cipher_info) > 0 else 'Unknown'
                            ssl_info['cipher_protocol'] = cipher_info[1] if len(cipher_info) > 1 else 'Unknown'
                            ssl_info['cipher_bits'] = cipher_info[2] if len(cipher_info) > 2 else 0
                        
                        ssl_info['protocol_version'] = ssock.version()
                        
                        # Security analysis
                        ssl_info['security_analysis'] = self._analyze_ssl_security(ssl_info, cert)
                        
                        # Public key information
                        ssl_info['public_key_info'] = self._extract_public_key_info(cert)
                        
                        # Certificate extensions
                        ssl_info['extensions'] = self._parse_certificate_extensions(cert)
                        
        except Exception as e:
            ssl_info['error'] = str(e)[:MAX_ERROR_LENGTH]
            
        return ssl_info
    
    def _analyze_ssl_security(self, ssl_info, cert):
        """Analyze SSL certificate and connection security"""
        analysis = {
            'security_level': 'Unknown',
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Check cipher strength
            cipher_bits = ssl_info.get('cipher_bits', 0)
            if cipher_bits < 128:
                analysis['warnings'].append(f"Weak cipher strength: {cipher_bits} bits")
                analysis['security_level'] = 'Weak'
            elif cipher_bits < 256:
                analysis['security_level'] = 'Moderate'
            else:
                analysis['security_level'] = 'Strong'
            
            # Check protocol version
            protocol = ssl_info.get('protocol_version', '')
            if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                analysis['warnings'].append(f"Outdated protocol: {protocol}")
                analysis['recommendations'].append("Upgrade to TLS 1.2 or higher")
            
            # Check certificate validity period
            validity_days = ssl_info.get('validity_period_days', 0)
            if validity_days > 825:  # More than ~2.3 years
                analysis['warnings'].append(f"Long validity period: {validity_days} days")
                analysis['recommendations'].append("Consider shorter certificate validity periods")
            
            # Check expiration
            days_until_expiry = ssl_info.get('days_until_expiry', 0)
            if days_until_expiry < 30:
                analysis['warnings'].append(f"Certificate expires soon: {days_until_expiry} days")
                analysis['recommendations'].append("Renew certificate soon")
            
            # Check for self-signed
            if ssl_info.get('is_self_signed', False):
                analysis['warnings'].append("Self-signed certificate")
                analysis['recommendations'].append("Use CA-issued certificate for production")
            
            # Check common name vs SAN
            subject_cn = ssl_info.get('subject', {}).get('commonName', '')
            san_dns = ssl_info.get('san_dns_names', [])
            if subject_cn and subject_cn not in san_dns:
                analysis['warnings'].append("Common Name not in Subject Alternative Names")
            
        except Exception as e:
            analysis['error'] = str(e)[:MAX_ERROR_LENGTH]
            
        return analysis
    
    def _extract_public_key_info(self, cert):
        """Extract public key information from certificate"""
        pub_key_info = {}
        
        try:
            # This is a simplified extraction - in real implementation,
            # you might want to use cryptography library for more details
            pub_key_info['algorithm'] = 'Unknown'
            pub_key_info['key_size'] = 'Unknown'
            
            # Try to extract from certificate extensions or other fields
            # This would require more advanced parsing with cryptography library
            
        except Exception as e:
            pub_key_info['error'] = str(e)[:MAX_ERROR_LENGTH]
            
        return pub_key_info
    
    def _parse_certificate_extensions(self, cert):
        """Parse certificate extensions"""
        extensions = {}
        
        try:
            # Basic extensions that are available in the standard cert dict
            if 'subjectAltName' in cert:
                extensions['Subject Alternative Name'] = cert['subjectAltName']
            
            # For more detailed extension parsing, you would need the cryptography library
            # extensions['Key Usage'] = 'Would need cryptography library'
            # extensions['Extended Key Usage'] = 'Would need cryptography library'
            # extensions['Basic Constraints'] = 'Would need cryptography library'
            
        except Exception as e:
            extensions['error'] = str(e)[:MAX_ERROR_LENGTH]
            
        return extensions
    
    def _parse_x509_certificate(self, cert_obj):
        """Parse X.509 certificate object into standard format"""
        try:
            # Extract subject and issuer
            subject = []
            for attribute in cert_obj.subject:
                subject.append([attribute.oid._name, attribute.value])
            
            issuer = []
            for attribute in cert_obj.issuer:
                issuer.append([attribute.oid._name, attribute.value])
            
            # Extract dates (use UTC versions to avoid deprecation warning)
            try:
                not_before = cert_obj.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y %Z')
                not_after = cert_obj.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y %Z')
            except AttributeError:
                # Fallback for older cryptography versions
                not_before = cert_obj.not_valid_before.strftime('%b %d %H:%M:%S %Y %Z')
                not_after = cert_obj.not_valid_after.strftime('%b %d %H:%M:%S %Y %Z')
            
            # Extract extensions
            extensions = {}
            try:
                san_ext = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = []
                for name in san_ext.value:
                    if hasattr(name, 'value'):
                        san_list.append(('DNS', name.value))
                    elif hasattr(name, 'ip_address'):
                        san_list.append(('IP Address', str(name.ip_address)))
                extensions['subjectAltName'] = san_list
            except:
                extensions['subjectAltName'] = []
            
            return {
                'subject': subject,
                'issuer': issuer,
                'version': cert_obj.version.value + 1,  # X.509 versions are 0-indexed
                'serialNumber': str(cert_obj.serial_number),
                'notBefore': not_before,
                'notAfter': not_after,
                'subjectAltName': extensions.get('subjectAltName', [])
            }
            
        except Exception as e:
            return {'error': str(e)[:MAX_ERROR_LENGTH]}
    
    def test_http_connectivity(self, ip, port):
        """Test HTTP/HTTPS connectivity to a specific IP:port"""
        results = {
            'http': {'status': False, 'code': None, 'title': None, 'error': None},
            'https': {'status': False, 'code': None, 'title': None, 'error': None, 'is_self_signed': False}
        }
        
        # Test HTTP
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            results['http']['status'] = True
            results['http']['code'] = response.status_code
            
            # Try to extract title from HTML and save body
            if 'text/html' in response.headers.get('content-type', '').lower():
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    results['http']['title'] = title_match.group(1).strip()[:MAX_TITLE_LENGTH]
            
            # Save response body (safely for JSON)
            body_text = response.text[:MAX_BODY_SIZE] if response.text else ""
            results['http']['body'] = body_text
                    
        except Exception as e:
            results['http']['error'] = str(e)[:MAX_ERROR_LENGTH]
        
        # Test HTTPS
        try:
            url = f"https://{ip}:{port}"
            
            # First try with verification to check if certificate is valid
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=True)
                results['https']['is_self_signed'] = False  # Valid certificate
            except requests.exceptions.SSLError:
                # SSL error - likely self-signed or invalid certificate
                response = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                results['https']['is_self_signed'] = True  # Self-signed or invalid
            
            results['https']['status'] = True
            results['https']['code'] = response.status_code
            
            # Get SSL certificate information using a separate connection (optimized)
            # This is still needed because requests doesn't expose detailed cert info
            if self.detailed_ssl:
                ssl_cert_info = self.get_ssl_certificate_info(ip, port, detailed=True)
                results['https']['ssl_certificate'] = ssl_cert_info
            else:
                # Minimal SSL info for fast scanning
                results['https']['ssl_certificate'] = {
                    'cipher_suite': 'Unknown',
                    'protocol_version': 'Unknown'
                }
            
            # Try to extract title from HTML and save body
            if 'text/html' in response.headers.get('content-type', '').lower():
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    results['https']['title'] = title_match.group(1).strip()[:MAX_TITLE_LENGTH]
            
            # Save response body (safely for JSON)
            body_text = response.text[:MAX_BODY_SIZE] if response.text else ""
            results['https']['body'] = body_text
                    
        except Exception as e:
            results['https']['error'] = str(e)[:MAX_ERROR_LENGTH]
        
        return results
    
    def validate_http_ports_threaded(self, ip_port_list):
        """Validate HTTP/HTTPS connectivity on multiple IP:port combinations using optimal concurrency"""
        if not ip_port_list:
            return {}
        
        logger.info(f"🌐 Starting HTTP/HTTPS validation for {len(ip_port_list)} IP:port combinations...")
        logger.info(f"🧵 Threads: {self.max_threads}, Timeout: {self.timeout}s")
        
        http_results = {}
        
        # Always use multiprocessing when enabled (better performance than threading)
        use_mp = self.use_multiprocessing
        
        if use_mp:
            # Use multiprocessing for better performance (bypasses GIL)
            logger.info(f"🚀 Using {self.max_processes} processes for multiprocessing...")
            
            with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
                # Prepare arguments for worker function
                worker_args = [
                    (ip, port, self.timeout, self.detailed_ssl)
                    for ip, port in ip_port_list
                ]
                
                # Submit all HTTP validation tasks
                future_to_target = {
                    executor.submit(test_http_connectivity_worker, args): f"{args[0]}:{args[1]}"
                    for args in worker_args
                }
        else:
            # Fallback to threading (if multiprocessing disabled)
            logger.info(f"🧵 Using {self.max_threads} threads for threading...")
            
            # Use ThreadPoolExecutor for concurrent HTTP validation
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all HTTP validation tasks
                future_to_target = {
                    executor.submit(self.test_http_connectivity, ip, port): f"{ip}:{port}"
                    for ip, port in ip_port_list
                }
        
        # Collect results as they complete (common for both threading and multiprocessing)
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
                logger.info(f"[{completed}/{len(ip_port_list)}] {target}: {http_status}HTTP {https_status}HTTPS{detail_str}")
                
            except Exception as e:
                http_results[target] = {
                    'http': {'status': False, 'error': str(e)},
                    'https': {'status': False, 'error': str(e)}
                }
                logger.info(f"[{completed}/{len(ip_port_list)}] {target}: Validation error - {e}")
        
        # Summary
        http_success = sum(1 for r in http_results.values() if r['http']['status'])
        https_success = sum(1 for r in http_results.values() if r['https']['status'])
        logger.info(f"📊 HTTP validation results: {http_success} HTTP, {https_success} HTTPS successful")
        
        return http_results
