# 🛡️ Security Headers Checker

A professional, production-ready command-line tool for analyzing HTTP security headers. This tool helps security professionals, developers, and system administrators assess the security posture of web applications by analyzing critical security headers and providing actionable recommendations.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-headers-brightgreen.svg)](https://securityheaders.com)

## 🎯 Overview

The Security Headers Checker performs comprehensive analysis of HTTP security headers to identify vulnerabilities and misconfigurations. It provides detailed reports with security scores, grades, and specific recommendations to improve your web application's security posture.

### ✨ Key Features

- **Comprehensive Analysis**: Analyzes 7+ critical security headers including CSP, HSTS, X-Frame-Options, and more
- **Professional Reporting**: Multiple output formats (console, JSON, HTML) with color-coded results
- **Batch Scanning**: Scan multiple URLs from a file with progress indicators
- **Smart Analysis**: Quality assessment beyond just header presence - analyzes configuration strength
- **Robust Scanning**: Built-in retry logic, timeout handling, and error management
- **Security Scoring**: A-F grading system with detailed breakdowns
- **Production Ready**: Comprehensive error handling, logging, and professional code structure

## 🚀 Quick Start

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/security-headers-checker.git
   cd security-headers-checker
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run your first scan**:
   ```bash
   python security_headers_checker.py --url https://example.com
   ```

### Basic Usage Examples

```bash
# Scan a single website
python security_headers_checker.py --url https://github.com

# Scan multiple websites from a file
python security_headers_checker.py --file examples/sample_urls.txt

# Generate detailed HTML report
python security_headers_checker.py --url https://example.com --format html --output report.html

# Batch scan with JSON output
python security_headers_checker.py --file urls.txt --format json --output results.json

# Verbose scanning with detailed analysis
python security_headers_checker.py --url https://example.com --verbose --details
```

## 📋 Analyzed Security Headers

| Header | Importance | Description |
|--------|------------|-------------|
| **Content-Security-Policy** | Critical | Prevents XSS attacks by controlling resource loading |
| **Strict-Transport-Security** | Critical | Enforces HTTPS and prevents downgrade attacks |
| **X-Frame-Options** | High | Prevents clickjacking attacks |
| **X-Content-Type-Options** | Medium | Prevents MIME sniffing attacks |
| **Referrer-Policy** | Medium | Controls referrer information leakage |
| **Permissions-Policy** | Medium | Controls browser feature access |
| **X-XSS-Protection** | Low | Legacy XSS protection (superseded by CSP) |

## 💻 Command Line Options

### Input Options
```bash
--url, -u          Single URL to scan
--file, -f         File containing list of URLs
```

### Output Options
```bash
--format           Output format: console, json, html (default: console)
--output, -o       Output file path
--no-colors        Disable colored output
--details          Show detailed header analysis
--include-raw      Include raw HTTP headers in JSON output
```

### Scanning Options
```bash
--timeout          Request timeout in seconds (default: 10)
--retries          Maximum retry attempts (default: 3)
--no-redirects     Don't follow HTTP redirects
```

### Verbosity Options
```bash
--verbose, -v      Enable verbose output
--quiet, -q        Quiet mode (errors only)
```

## 📊 Sample Output

### Console Output
```
🛡️ Security Headers Analysis Report
Generated: 2024-01-15 14:30:25
Total URLs scanned: 1

[1] https://github.com
Score: 85.2 | Grade: B | Response Time: 0.847s

🔍 HEADERS ANALYSIS
  ✅ Content-Security-Policy 🟡 (20.5/25)
     ⚠️ Contains 'unsafe-inline' which reduces XSS protection
  ✅ Strict-Transport-Security 🟢 (20.0/20)
  ✅ X-Frame-Options 🟢 (15.0/15)
  ✅ X-Content-Type-Options 🟢 (10.0/10)
  ❌ Referrer-Policy
  ❌ Permissions-Policy
  ✅ X-XSS-Protection 🟡 (5.0/5)

💡 RECOMMENDATIONS
  1. MEDIUM: Add these important security headers: referrer-policy, permissions-policy
  2. MEDIUM: Fix problematic header configurations:
     • Contains 'unsafe-inline' which reduces XSS protection
  3. Consider implementing a stricter CSP policy without unsafe-inline
```

### HTML Report
The HTML report provides a professional, comprehensive analysis with:
- Executive summary with statistics
- Interactive grade distribution
- Detailed per-URL analysis
- Color-coded header status
- Exportable JSON data
- Print-friendly styling

## 📁 Project Structure

```
security-headers-checker/
├── security_headers_checker.py    # Main CLI application
├── modules/
│   ├── __init__.py
│   ├── scanner.py                 # HTTP scanning logic
│   ├── analyzer.py                # Header analysis and scoring
│   └── reporter.py                # Report generation
├── config/
│   └── header_rules.json          # Header analysis rules
├── templates/
│   └── report_template.html       # HTML report template
├── examples/
│   ├── sample_urls.txt            # Example URL list
│   └── sample_config.json         # Example configuration
├── requirements.txt               # Python dependencies
├── setup.py                      # Package installation
└── README.md                     # This file
```

## ⚙️ Configuration

### Custom Configuration File

You can customize the analysis rules and scoring by creating a configuration file:

```bash
python security_headers_checker.py --config my_config.json --url https://example.com
```

See `examples/sample_config.json` for a complete configuration example with:
- Custom scoring weights
- Additional analysis rules
- Modified grade thresholds
- Advanced checking options

### URL List File Format

Create a text file with one URL per line:

```
# Security Headers Test URLs
https://github.com
https://stackoverflow.com
https://owasp.org

# Add your URLs here
https://your-website.com
```

Lines starting with `#` are treated as comments and ignored.

## 🔧 Advanced Usage

### Integration with CI/CD

```bash
# Exit with error code if average score is below threshold
python security_headers_checker.py --file production_urls.txt --format json --quiet | jq '.summary.average_score < 80' && exit 1
```

### Automated Reporting

```bash
#!/bin/bash
# Generate daily security report
DATE=$(date +%Y-%m-%d)
python security_headers_checker.py \
    --file production_urls.txt \
    --format html \
    --output "reports/security-report-$DATE.html"
```

### Custom Analysis

```python
from modules.scanner import SecurityHeadersScanner
from modules.analyzer import SecurityHeadersAnalyzer

# Custom scanning logic
scanner = SecurityHeadersScanner({'timeout': 30})
analyzer = SecurityHeadersAnalyzer()

result = scanner.scan_url('https://example.com')
analysis = analyzer.analyze_headers(result)
print(f"Security Score: {analysis['score']}")
```

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/your-username/security-headers-checker.git
cd security-headers-checker

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

### Project Architecture

- **scanner.py**: Handles HTTP requests with robust error handling and retry logic
- **analyzer.py**: Analyzes headers and calculates security scores using configurable rules
- **reporter.py**: Generates reports in multiple formats with professional styling
- **security_headers_checker.py**: Main CLI interface with comprehensive argument parsing

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Areas for Contribution
- Additional security headers analysis
- New output formats
- Performance optimizations
- Test coverage improvements
- Documentation enhancements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security Considerations

This tool is designed for defensive security purposes only:
- Analyzes publicly available HTTP headers
- Does not perform any invasive testing
- Respects robots.txt and rate limiting
- Suitable for authorized security assessments

## 📞 Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/your-username/security-headers-checker/issues)
- **Documentation**: See examples and configuration in the `examples/` directory
- **Security**: For security-related concerns, please contact [security@example.com](mailto:security@example.com)

## 🏆 Acknowledgments

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Security Headers Community](https://securityheaders.com/)

---

**Built for cybersecurity professionals by cybersecurity professionals.** 🛡️
