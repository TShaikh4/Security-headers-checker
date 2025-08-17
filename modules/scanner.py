"""
HTTP Scanner Module

This module handles HTTP requests to scan websites for security headers.
Includes robust error handling, retry logic, and timeout management.
"""

import requests
import time
import logging
from urllib.parse import urlparse
from typing import Dict, Optional, List, Tuple
import random


class SecurityHeadersScanner:
    """
    A robust HTTP scanner for analyzing security headers.
    
    Features:
    - Configurable timeouts and retries
    - Multiple user agent support
    - Comprehensive error handling
    - SSL verification options
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Configuration dictionary containing scan settings
        """
        self.timeout = config.get('timeout', 10)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1)
        self.user_agents = config.get('user_agents', [
            'Mozilla/5.0 (Security-Headers-Checker/1.0)'
        ])
        
        self.logger = logging.getLogger(__name__)
        
        # Create session with connection pooling
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL format and accessibility.
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, normalized_url_or_error_message)
        """
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            parsed = urlparse(url)
            
            if not parsed.netloc:
                return False, "Invalid URL format: missing domain"
                
            if parsed.scheme not in ['http', 'https']:
                return False, "Invalid URL scheme: must be http or https"
                
            return True, url
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def scan_url(self, url: str, follow_redirects: bool = True) -> Dict:
        """
        Scan a single URL for security headers.
        
        Args:
            url: URL to scan
            follow_redirects: Whether to follow HTTP redirects
            
        Returns:
            Dictionary containing scan results
        """
        # Validate URL first
        is_valid, result = self.validate_url(url)
        if not is_valid:
            return {
                'url': url,
                'success': False,
                'error': result,
                'headers': {},
                'status_code': None,
                'response_time': None
            }
        
        url = result  # Use normalized URL
        
        # Attempt scan with retries
        for attempt in range(self.max_retries + 1):
            try:
                return self._perform_scan(url, follow_redirects, attempt)
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Scan attempt {attempt + 1} failed for {url}: {str(e)}")
                
                if attempt < self.max_retries:
                    # Exponential backoff with jitter
                    delay = self.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(delay)
                else:
                    return {
                        'url': url,
                        'success': False,
                        'error': f"Failed after {self.max_retries + 1} attempts: {str(e)}",
                        'headers': {},
                        'status_code': None,
                        'response_time': None
                    }
    
    def _perform_scan(self, url: str, follow_redirects: bool, attempt: int) -> Dict:
        """
        Perform the actual HTTP request and header extraction.
        
        Args:
            url: URL to scan
            follow_redirects: Whether to follow redirects
            attempt: Current attempt number
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        # Rotate user agents
        user_agent = self.user_agents[attempt % len(self.user_agents)]
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=follow_redirects,
                verify=True  # Always verify SSL certificates for security
            )
            
            response_time = time.time() - start_time
            
            # Extract security-relevant headers
            security_headers = self._extract_security_headers(response.headers)
            
            # Check for redirect information
            redirect_info = None
            if response.history:
                redirect_info = {
                    'redirected': True,
                    'redirect_chain': [r.url for r in response.history],
                    'final_url': response.url
                }
            
            return {
                'url': url,
                'final_url': response.url if response.history else url,
                'success': True,
                'error': None,
                'headers': security_headers,
                'all_headers': dict(response.headers),
                'status_code': response.status_code,
                'response_time': round(response_time, 3),
                'redirect_info': redirect_info,
                'server': response.headers.get('Server', 'Unknown'),
                'scan_timestamp': time.time()
            }
            
        except requests.exceptions.SSLError as e:
            return {
                'url': url,
                'success': False,
                'error': f"SSL/TLS error: {str(e)}",
                'headers': {},
                'status_code': None,
                'response_time': None
            }
            
        except requests.exceptions.Timeout as e:
            return {
                'url': url,
                'success': False,
                'error': f"Request timeout after {self.timeout} seconds",
                'headers': {},
                'status_code': None,
                'response_time': None
            }
            
        except requests.exceptions.ConnectionError as e:
            return {
                'url': url,
                'success': False,
                'error': f"Connection error: {str(e)}",
                'headers': {},
                'status_code': None,
                'response_time': None
            }
    
    def _extract_security_headers(self, response_headers: Dict) -> Dict:
        """
        Extract security-relevant headers from HTTP response.
        
        Args:
            response_headers: HTTP response headers
            
        Returns:
            Dictionary of security headers with normalized names
        """
        security_header_names = {
            'content-security-policy',
            'content-security-policy-report-only',
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'referrer-policy',
            'permissions-policy',
            'feature-policy',  # Legacy name for permissions-policy
            'x-xss-protection',
            'x-permitted-cross-domain-policies',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy'
        }
        
        extracted_headers = {}
        
        for header_name, header_value in response_headers.items():
            normalized_name = header_name.lower()
            
            if normalized_name in security_header_names:
                extracted_headers[normalized_name] = header_value.strip()
        
        return extracted_headers
    
    def scan_multiple_urls(self, urls: List[str], progress_callback=None) -> List[Dict]:
        """
        Scan multiple URLs and return results.
        
        Args:
            urls: List of URLs to scan
            progress_callback: Optional callback function for progress updates
            
        Returns:
            List of scan results
        """
        results = []
        total_urls = len(urls)
        
        for i, url in enumerate(urls):
            self.logger.info(f"Scanning {i + 1}/{total_urls}: {url}")
            
            result = self.scan_url(url)
            results.append(result)
            
            # Call progress callback if provided
            if progress_callback:
                progress_callback(i + 1, total_urls, url, result['success'])
                
        return results
    
    def close(self):
        """Close the HTTP session."""
        if hasattr(self, 'session'):
            self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()