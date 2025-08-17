"""
Security Headers Analyzer Module

This module analyzes security headers and calculates security scores.
Provides detailed analysis of header quality and security implications.
"""

import re
import json
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path


class SecurityHeadersAnalyzer:
    """
    Analyzes security headers and calculates security scores.
    
    Features:
    - Comprehensive header analysis
    - A-F grading system
    - Detailed recommendations
    - Quality assessment beyond presence
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the analyzer with header rules.
        
        Args:
            config_path: Path to header rules configuration file
        """
        self.logger = logging.getLogger(__name__)
        
        if config_path is None:
            # Default to config file in the same directory structure
            config_path = Path(__file__).parent.parent / 'config' / 'header_rules.json'
        
        self.rules = self._load_rules(config_path)
        self.header_definitions = self.rules.get('headers', {})
        self.scoring_config = self.rules.get('scoring', {})
        
    def _load_rules(self, config_path: str) -> Dict:
        """
        Load header analysis rules from configuration file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dictionary containing header rules and scoring configuration
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {config_path}")
            return self._get_default_rules()
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict:
        """
        Provide default rules if configuration file is not available.
        
        Returns:
            Default header rules dictionary
        """
        return {
            'headers': {
                'content-security-policy': {'score_weight': 25, 'importance': 'critical'},
                'strict-transport-security': {'score_weight': 20, 'importance': 'critical'},
                'x-frame-options': {'score_weight': 15, 'importance': 'high'},
                'x-content-type-options': {'score_weight': 10, 'importance': 'medium'},
                'referrer-policy': {'score_weight': 10, 'importance': 'medium'},
                'permissions-policy': {'score_weight': 10, 'importance': 'medium'},
                'x-xss-protection': {'score_weight': 5, 'importance': 'low'}
            },
            'scoring': {
                'grade_thresholds': {'A': 90, 'B': 80, 'C': 70, 'D': 60, 'F': 0}
            }
        }
    
    def analyze_headers(self, scan_result: Dict) -> Dict:
        """
        Analyze security headers from a scan result.
        
        Args:
            scan_result: Result from scanner module
            
        Returns:
            Dictionary containing detailed analysis results
        """
        if not scan_result.get('success', False):
            return {
                'url': scan_result.get('url', ''),
                'scan_successful': False,
                'error': scan_result.get('error', 'Unknown error'),
                'grade': 'F',
                'score': 0,
                'headers_analysis': {},
                'recommendations': ['Unable to scan URL: ' + scan_result.get('error', 'Unknown error')]
            }
        
        headers = scan_result.get('headers', {})
        analysis_result = {
            'url': scan_result.get('url', ''),
            'final_url': scan_result.get('final_url', ''),
            'scan_successful': True,
            'error': None,
            'server': scan_result.get('server', 'Unknown'),
            'response_time': scan_result.get('response_time'),
            'status_code': scan_result.get('status_code'),
            'redirect_info': scan_result.get('redirect_info'),
            'headers_analysis': {},
            'score': 0,
            'grade': 'F',
            'recommendations': [],
            'security_summary': {
                'critical_missing': [],
                'high_missing': [],
                'medium_missing': [],
                'present_headers': [],
                'problematic_configurations': []
            }
        }
        
        total_score = 0
        max_possible_score = 0
        
        # Analyze each header type
        for header_key, header_config in self.header_definitions.items():
            max_possible_score += header_config.get('score_weight', 0)
            
            header_analysis = self._analyze_single_header(
                header_key, 
                headers.get(header_key), 
                header_config
            )
            
            analysis_result['headers_analysis'][header_key] = header_analysis
            total_score += header_analysis['score']
            
            # Categorize missing headers by importance
            if not header_analysis['present']:
                importance = header_config.get('importance', 'medium')
                if importance == 'critical':
                    analysis_result['security_summary']['critical_missing'].append(header_key)
                elif importance == 'high':
                    analysis_result['security_summary']['high_missing'].append(header_key)
                else:
                    analysis_result['security_summary']['medium_missing'].append(header_key)
            else:
                analysis_result['security_summary']['present_headers'].append(header_key)
                
                # Check for problematic configurations
                if header_analysis.get('issues'):
                    analysis_result['security_summary']['problematic_configurations'].extend(
                        header_analysis['issues']
                    )
        
        # Calculate final score and grade
        if max_possible_score > 0:
            final_score = (total_score / max_possible_score) * 100
        else:
            final_score = 0
            
        analysis_result['score'] = round(final_score, 1)
        analysis_result['grade'] = self._calculate_grade(final_score)
        analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
        
        return analysis_result
    
    def _analyze_single_header(self, header_key: str, header_value: Optional[str], 
                             header_config: Dict) -> Dict:
        """
        Analyze a single security header.
        
        Args:
            header_key: Header name (normalized)
            header_value: Header value (None if not present)
            header_config: Configuration for this header type
            
        Returns:
            Dictionary containing analysis of this specific header
        """
        analysis = {
            'name': header_config.get('name', header_key),
            'present': header_value is not None,
            'value': header_value,
            'score': 0,
            'max_score': header_config.get('score_weight', 0),
            'quality': 'missing',
            'issues': [],
            'recommendations': header_config.get('recommendations', [])
        }
        
        if not analysis['present']:
            return analysis
        
        # Header is present, now analyze its quality
        analysis['quality'] = 'present'
        base_score = header_config.get('score_weight', 0)
        
        # Perform specific analysis based on header type
        if header_key == 'content-security-policy':
            analysis.update(self._analyze_csp(header_value, base_score))
        elif header_key == 'strict-transport-security':
            analysis.update(self._analyze_hsts(header_value, base_score))
        elif header_key == 'x-frame-options':
            analysis.update(self._analyze_frame_options(header_value, base_score))
        elif header_key == 'x-content-type-options':
            analysis.update(self._analyze_content_type_options(header_value, base_score))
        elif header_key == 'referrer-policy':
            analysis.update(self._analyze_referrer_policy(header_value, base_score))
        elif header_key == 'permissions-policy':
            analysis.update(self._analyze_permissions_policy(header_value, base_score))
        elif header_key == 'x-xss-protection':
            analysis.update(self._analyze_xss_protection(header_value, base_score))
        else:
            # Default scoring for unknown headers
            analysis['score'] = base_score
            analysis['quality'] = 'present'
        
        return analysis
    
    def _analyze_csp(self, value: str, base_score: int) -> Dict:
        """Analyze Content-Security-Policy header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        value_lower = value.lower()
        
        # Check for unsafe practices
        if "'unsafe-inline'" in value_lower:
            analysis['issues'].append("Contains 'unsafe-inline' which reduces XSS protection")
            analysis['score'] -= base_score * 0.3
            analysis['quality'] = 'weak'
            
        if "'unsafe-eval'" in value_lower:
            analysis['issues'].append("Contains 'unsafe-eval' which allows dynamic code execution")
            analysis['score'] -= base_score * 0.3
            analysis['quality'] = 'weak'
            
        # Check for overly permissive policies
        if value_lower.count('*') > 2:
            analysis['issues'].append("Multiple wildcard sources reduce CSP effectiveness")
            analysis['score'] -= base_score * 0.2
            
        # Bonus for good practices
        if 'nonce-' in value_lower or "'sha256-" in value_lower:
            analysis['score'] += base_score * 0.1
            analysis['quality'] = 'excellent'
            
        return analysis
    
    def _analyze_hsts(self, value: str, base_score: int) -> Dict:
        """Analyze Strict-Transport-Security header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        # Extract max-age value
        max_age_match = re.search(r'max-age=(\d+)', value.lower())
        if max_age_match:
            max_age = int(max_age_match.group(1))
            
            if max_age < 31536000:  # Less than 1 year
                analysis['issues'].append(f"max-age of {max_age} is less than recommended 1 year (31536000)")
                analysis['score'] -= base_score * 0.2
                analysis['quality'] = 'weak'
        else:
            analysis['issues'].append("Missing or invalid max-age directive")
            analysis['score'] -= base_score * 0.5
            analysis['quality'] = 'poor'
            
        # Check for includeSubDomains
        if 'includesubdomains' not in value.lower():
            analysis['issues'].append("Missing includeSubDomains directive")
            analysis['score'] -= base_score * 0.1
            
        # Bonus for preload
        if 'preload' in value.lower():
            analysis['score'] += base_score * 0.1
            analysis['quality'] = 'excellent'
            
        return analysis
    
    def _analyze_frame_options(self, value: str, base_score: int) -> Dict:
        """Analyze X-Frame-Options header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        value_upper = value.upper().strip()
        
        if value_upper == 'DENY':
            analysis['quality'] = 'excellent'
        elif value_upper == 'SAMEORIGIN':
            analysis['quality'] = 'good'
        elif value_upper.startswith('ALLOW-FROM'):
            analysis['quality'] = 'acceptable'
            analysis['issues'].append("ALLOW-FROM is deprecated, consider using CSP frame-ancestors")
        else:
            analysis['issues'].append(f"Invalid or unknown value: {value}")
            analysis['score'] -= base_score * 0.5
            analysis['quality'] = 'poor'
            
        return analysis
    
    def _analyze_content_type_options(self, value: str, base_score: int) -> Dict:
        """Analyze X-Content-Type-Options header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        if value.lower().strip() != 'nosniff':
            analysis['issues'].append(f"Should be 'nosniff', found: {value}")
            analysis['score'] -= base_score * 0.5
            analysis['quality'] = 'poor'
        else:
            analysis['quality'] = 'excellent'
            
        return analysis
    
    def _analyze_referrer_policy(self, value: str, base_score: int) -> Dict:
        """Analyze Referrer-Policy header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        safe_policies = [
            'no-referrer', 'strict-origin', 'strict-origin-when-cross-origin',
            'same-origin'
        ]
        
        risky_policies = ['unsafe-url', 'no-referrer-when-downgrade']
        
        value_lower = value.lower().strip()
        
        if value_lower in risky_policies:
            analysis['issues'].append(f"Policy '{value}' may leak sensitive information")
            analysis['score'] -= base_score * 0.3
            analysis['quality'] = 'weak'
        elif value_lower in safe_policies:
            analysis['quality'] = 'excellent'
            
        return analysis
    
    def _analyze_permissions_policy(self, value: str, base_score: int) -> Dict:
        """Analyze Permissions-Policy header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        # Count number of restricted features
        feature_count = value.count('=')
        
        if feature_count >= 5:
            analysis['quality'] = 'excellent'
            analysis['score'] += base_score * 0.1
        elif feature_count >= 3:
            analysis['quality'] = 'good'
        else:
            analysis['quality'] = 'basic'
            
        return analysis
    
    def _analyze_xss_protection(self, value: str, base_score: int) -> Dict:
        """Analyze X-XSS-Protection header."""
        analysis = {'score': base_score, 'quality': 'good'}
        
        if value.strip() == '0':
            analysis['issues'].append("XSS protection is disabled")
            analysis['score'] = 0
            analysis['quality'] = 'dangerous'
        elif '1; mode=block' in value.lower():
            analysis['quality'] = 'good'
        else:
            analysis['quality'] = 'basic'
            
        return analysis
    
    def _calculate_grade(self, score: float) -> str:
        """
        Calculate letter grade based on score.
        
        Args:
            score: Numerical score (0-100)
            
        Returns:
            Letter grade (A-F)
        """
        thresholds = self.scoring_config.get('grade_thresholds', {
            'A': 90, 'B': 80, 'C': 70, 'D': 60, 'F': 0
        })
        
        for grade, threshold in thresholds.items():
            if score >= threshold:
                return grade
        
        return 'F'
    
    def _generate_recommendations(self, analysis_result: Dict) -> List[str]:
        """
        Generate prioritized recommendations based on analysis.
        
        Args:
            analysis_result: Complete analysis result
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        summary = analysis_result['security_summary']
        
        # Critical missing headers
        if summary['critical_missing']:
            recommendations.append(
                f"CRITICAL: Implement these essential security headers: {', '.join(summary['critical_missing'])}"
            )
        
        # High importance missing headers
        if summary['high_missing']:
            recommendations.append(
                f"HIGH: Add these important security headers: {', '.join(summary['high_missing'])}"
            )
        
        # Problematic configurations
        if summary['problematic_configurations']:
            recommendations.append(
                "MEDIUM: Fix problematic header configurations:"
            )
            for issue in summary['problematic_configurations'][:3]:  # Limit to top 3
                recommendations.append(f"  • {issue}")
        
        # Medium importance missing headers
        if summary['medium_missing']:
            recommendations.append(
                f"MEDIUM: Consider adding: {', '.join(summary['medium_missing'])}"
            )
        
        # General advice based on grade
        grade = analysis_result['grade']
        if grade in ['D', 'F']:
            recommendations.append(
                "Start with implementing Content-Security-Policy and Strict-Transport-Security"
            )
        elif grade == 'C':
            recommendations.append(
                "Good foundation! Focus on fixing configuration issues and adding missing headers"
            )
        elif grade in ['A', 'B']:
            recommendations.append(
                "Excellent security posture! Regularly review and update your policies"
            )
        
        return recommendations[:10]  # Limit to top 10 recommendations