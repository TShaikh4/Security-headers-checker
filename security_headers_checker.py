#!/usr/bin/env python3
"""
Security Headers Checker - Professional tool for analyzing HTTP security headers

A comprehensive security analysis tool that scans websites for security headers,
analyzes their configuration quality, and provides detailed reports with
actionable recommendations.

Usage:
    python security_headers_checker.py --url https://example.com
    python security_headers_checker.py --file urls.txt --format json
    python security_headers_checker.py --url example.com --output report.html
"""

import argparse
import logging
import sys
import json
from pathlib import Path
from typing import List, Dict

# Import our modules
from modules.scanner import SecurityHeadersScanner
from modules.analyzer import SecurityHeadersAnalyzer
from modules.reporter import SecurityHeadersReporter


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """
    Configure logging based on verbosity level.
    
    Args:
        verbose: Enable verbose output
        quiet: Enable quiet mode (errors only)
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def load_config(config_path: str = None) -> Dict:
    """
    Load configuration from file or use defaults.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    if config_path is None:
        config_path = Path(__file__).parent / 'config' / 'header_rules.json'
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config.get('scan_settings', {})
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        # Return default configuration
        return {
            'timeout': 10,
            'max_retries': 3,
            'retry_delay': 1,
            'user_agents': ['Mozilla/5.0 (Security-Headers-Checker/1.0)']
        }


def load_urls_from_file(file_path: str) -> List[str]:
    """
    Load URLs from a text file.
    
    Args:
        file_path: Path to file containing URLs
        
    Returns:
        List of URLs
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = []
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading file '{file_path}': {e}")
        sys.exit(1)


def validate_output_path(output_path: str, format_type: str) -> str:
    """
    Validate and normalize output file path.
    
    Args:
        output_path: Requested output path
        format_type: Output format (json, html, console)
        
    Returns:
        Validated output path
    """
    if not output_path:
        return None
    
    path = Path(output_path)
    
    # Add appropriate extension if missing
    extensions = {'json': '.json', 'html': '.html', 'console': '.txt'}
    expected_ext = extensions.get(format_type, '')
    
    if expected_ext and not path.suffix:
        path = path.with_suffix(expected_ext)
    
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    
    return str(path)


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description='Security Headers Checker - Analyze HTTP security headers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com
  %(prog)s --url example.com --verbose
  %(prog)s --file urls.txt --format json --output results.json
  %(prog)s --url https://example.com --format html --output report.html
  %(prog)s --file urls.txt --no-colors --quiet

Supported output formats:
  console    Colored console output (default)
  json       Machine-readable JSON format
  html       Professional HTML report

The tool analyzes these security headers:
  • Content-Security-Policy (CSP)
  • Strict-Transport-Security (HSTS)
  • X-Frame-Options
  • X-Content-Type-Options
  • Referrer-Policy
  • Permissions-Policy
  • X-XSS-Protection
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--url', '-u',
        help='Single URL to scan'
    )
    input_group.add_argument(
        '--file', '-f',
        help='File containing list of URLs to scan'
    )
    
    # Output options
    parser.add_argument(
        '--format',
        choices=['console', 'json', 'html'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout for console format)'
    )
    parser.add_argument(
        '--no-colors',
        action='store_true',
        help='Disable colored output'
    )
    
    # Scanning options
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--retries',
        type=int,
        default=3,
        help='Maximum retry attempts (default: 3)'
    )
    parser.add_argument(
        '--no-redirects',
        action='store_true',
        help='Do not follow HTTP redirects'
    )
    
    # Report options
    parser.add_argument(
        '--details',
        action='store_true',
        help='Show detailed header analysis in console output'
    )
    parser.add_argument(
        '--include-raw',
        action='store_true',
        help='Include raw HTTP headers in JSON output'
    )
    
    # Verbosity options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode - only show errors'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        help='Path to custom configuration file'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='version',
        version='Security Headers Checker 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.quiet)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override config with command line arguments
        if args.timeout:
            config['timeout'] = args.timeout
        if args.retries:
            config['max_retries'] = args.retries
        
        # Determine URLs to scan
        if args.url:
            urls = [args.url]
        else:
            urls = load_urls_from_file(args.file)
        
        if not urls:
            print("❌ No URLs to scan.")
            sys.exit(1)
        
        # Validate output path
        output_path = validate_output_path(args.output, args.format)
        
        # Initialize components
        scanner = SecurityHeadersScanner(config)
        analyzer = SecurityHeadersAnalyzer()
        reporter = SecurityHeadersReporter(use_colors=not args.no_colors)
        
        # Perform scanning
        if not args.quiet:
            print(f"🔍 Starting scan of {len(urls)} URL(s)...")
            print("")
        
        if len(urls) > 1 and not args.quiet:
            # Show progress for multiple URLs
            scan_results = scanner.scan_multiple_urls(
                urls, 
                progress_callback=reporter.print_progress
            )
        else:
            # Single URL scan
            scan_results = []
            for url in urls:
                result = scanner.scan_url(url, follow_redirects=not args.no_redirects)
                scan_results.append(result)
        
        # Analyze results
        if not args.quiet:
            print("\n📊 Analyzing security headers...")
        
        analysis_results = []
        for scan_result in scan_results:
            analysis = analyzer.analyze_headers(scan_result)
            analysis_results.append(analysis)
        
        # Generate and output report
        if args.format == 'console':
            report = reporter.generate_console_report(
                analysis_results, 
                show_details=args.details or len(urls) == 1
            )
            
            if output_path:
                reporter.save_report(report, output_path, 'console')
            else:
                print(report)
                
        elif args.format == 'json':
            report = reporter.generate_json_report(
                analysis_results,
                include_raw_headers=args.include_raw
            )
            
            if output_path:
                reporter.save_report(report, output_path, 'json')
            else:
                print(report)
                
        elif args.format == 'html':
            if not output_path:
                output_path = f"security_report_{len(urls)}_urls.html"
            
            report = reporter.generate_html_report(analysis_results)
            reporter.save_report(report, output_path, 'html')
        
        # Print summary if not quiet
        if not args.quiet and args.format == 'console':
            successful_scans = len([r for r in analysis_results if r.get('scan_successful', False)])
            failed_scans = len(analysis_results) - successful_scans
            
            print(f"\n✅ Scan complete: {successful_scans} successful, {failed_scans} failed")
            
            if successful_scans > 0:
                avg_score = sum(r.get('score', 0) for r in analysis_results if r.get('scan_successful', False)) / successful_scans
                print(f"📈 Average security score: {avg_score:.1f}")
    
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup
        if 'scanner' in locals():
            scanner.close()


if __name__ == '__main__':
    main()