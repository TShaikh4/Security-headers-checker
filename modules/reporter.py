"""
Reporting Module

This module handles output formatting and report generation.
Supports console, JSON, and HTML output formats with professional styling.
"""

import json
import logging
import sys
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

try:
    from colorama import init, Fore, Back, Style
    init()  # Initialize colorama for Windows compatibility
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback color codes for systems without colorama
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        RESET_ALL = '\033[0m'


class SecurityHeadersReporter:
    """
    Generates reports in multiple formats (console, JSON, HTML).
    
    Features:
    - Color-coded console output
    - Professional HTML reports
    - Structured JSON export
    - Progress indicators
    """
    
    def __init__(self, use_colors: bool = True):
        """
        Initialize the reporter.
        
        Args:
            use_colors: Whether to use colored output in console
        """
        self.use_colors = use_colors and COLORAMA_AVAILABLE
        self.logger = logging.getLogger(__name__)
        
    def generate_console_report(self, analysis_results: List[Dict], 
                              show_details: bool = True) -> str:
        """
        Generate a console-friendly report.
        
        Args:
            analysis_results: List of analysis results
            show_details: Whether to show detailed header analysis
            
        Returns:
            Formatted console report string
        """
        if not analysis_results:
            return self._color_text("No results to display.", Fore.YELLOW)
        
        report_lines = []
        
        # Header
        report_lines.append(self._format_header("Security Headers Analysis Report"))
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total URLs scanned: {len(analysis_results)}")
        report_lines.append("")
        
        # Summary statistics
        successful_scans = [r for r in analysis_results if r.get('scan_successful', False)]
        if successful_scans:
            avg_score = sum(r.get('score', 0) for r in successful_scans) / len(successful_scans)
            grade_counts = {}
            for result in successful_scans:
                grade = result.get('grade', 'F')
                grade_counts[grade] = grade_counts.get(grade, 0) + 1
            
            report_lines.append(self._color_text("📊 SUMMARY STATISTICS", Fore.CYAN, Style.BRIGHT))
            report_lines.append(f"Average Security Score: {self._format_score(avg_score)}")
            report_lines.append("Grade Distribution:")
            for grade in ['A', 'B', 'C', 'D', 'F']:
                count = grade_counts.get(grade, 0)
                if count > 0:
                    color = self._get_grade_color(grade)
                    report_lines.append(f"  {self._color_text(grade, color)}: {count} sites")
            report_lines.append("")
        
        # Individual results
        for i, result in enumerate(analysis_results, 1):
            report_lines.extend(self._format_single_result(result, i, show_details))
            if i < len(analysis_results):
                report_lines.append("─" * 80)
                report_lines.append("")
        
        return "\n".join(report_lines)
    
    def _format_single_result(self, result: Dict, index: int, show_details: bool) -> List[str]:
        """Format a single analysis result for console output."""
        lines = []
        
        # Result header
        url = result.get('url', 'Unknown URL')
        lines.append(self._color_text(f"[{index}] {url}", Fore.WHITE, Style.BRIGHT))
        
        if not result.get('scan_successful', False):
            error = result.get('error', 'Unknown error')
            lines.append(self._color_text(f"❌ Scan failed: {error}", Fore.RED))
            return lines
        
        # Basic info
        score = result.get('score', 0)
        grade = result.get('grade', 'F')
        response_time = result.get('response_time')
        
        lines.append(f"Score: {self._format_score(score)} | "
                    f"Grade: {self._format_grade(grade)} | "
                    f"Response Time: {response_time}s")
        
        # Redirect info
        if result.get('redirect_info', {}).get('redirected'):
            final_url = result.get('final_url', '')
            lines.append(self._color_text(f"🔀 Redirected to: {final_url}", Fore.YELLOW))
        
        if show_details:
            lines.extend(self._format_headers_analysis(result.get('headers_analysis', {})))
            lines.extend(self._format_recommendations(result.get('recommendations', [])))
        
        return lines
    
    def _format_headers_analysis(self, headers_analysis: Dict) -> List[str]:
        """Format detailed headers analysis for console."""
        lines = []
        
        if not headers_analysis:
            return lines
        
        lines.append(self._color_text("🔍 HEADERS ANALYSIS", Fore.CYAN))
        
        # Group headers by presence
        present_headers = []
        missing_headers = []
        
        for header_key, analysis in headers_analysis.items():
            header_name = analysis.get('name', header_key)
            
            if analysis.get('present', False):
                quality = analysis.get('quality', 'unknown')
                score = analysis.get('score', 0)
                max_score = analysis.get('max_score', 0)
                
                # Format quality indicator
                quality_indicator = self._get_quality_indicator(quality)
                score_text = f"({score:.1f}/{max_score})"
                
                present_headers.append(f"  ✅ {header_name} {quality_indicator} {score_text}")
                
                # Show issues if any
                issues = analysis.get('issues', [])
                for issue in issues:
                    present_headers.append(f"     {self._color_text('⚠️ ' + issue, Fore.YELLOW)}")
            else:
                missing_headers.append(f"  ❌ {header_name}")
        
        # Display present headers
        if present_headers:
            lines.extend(present_headers)
        
        # Display missing headers
        if missing_headers:
            if present_headers:
                lines.append("")
            lines.extend(missing_headers)
        
        return lines
    
    def _format_recommendations(self, recommendations: List[str]) -> List[str]:
        """Format recommendations for console output."""
        if not recommendations:
            return []
        
        lines = [self._color_text("💡 RECOMMENDATIONS", Fore.MAGENTA)]
        
        for i, recommendation in enumerate(recommendations[:5], 1):  # Limit to top 5
            # Color code by priority
            if recommendation.startswith('CRITICAL'):
                color = Fore.RED
            elif recommendation.startswith('HIGH'):
                color = Fore.YELLOW
            elif recommendation.startswith('MEDIUM'):
                color = Fore.CYAN
            else:
                color = Fore.WHITE
            
            lines.append(f"  {i}. {self._color_text(recommendation, color)}")
        
        return lines
    
    def generate_json_report(self, analysis_results: List[Dict], 
                           include_raw_headers: bool = False) -> str:
        """
        Generate a JSON report.
        
        Args:
            analysis_results: List of analysis results
            include_raw_headers: Whether to include raw HTTP headers
            
        Returns:
            JSON-formatted report string
        """
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_urls': len(analysis_results),
                'successful_scans': len([r for r in analysis_results if r.get('scan_successful', False)]),
                'tool_version': '1.0.0'
            },
            'summary': self._generate_summary_stats(analysis_results),
            'results': []
        }
        
        for result in analysis_results:
            cleaned_result = result.copy()
            
            # Remove raw headers if not requested
            if not include_raw_headers and 'all_headers' in cleaned_result:
                del cleaned_result['all_headers']
            
            report_data['results'].append(cleaned_result)
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def generate_html_report(self, analysis_results: List[Dict], 
                           template_path: Optional[str] = None) -> str:
        """
        Generate an HTML report.
        
        Args:
            analysis_results: List of analysis results
            template_path: Path to HTML template file
            
        Returns:
            HTML report string
        """
        if template_path is None:
            template_path = Path(__file__).parent.parent / 'templates' / 'report_template.html'
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except FileNotFoundError:
            # Use embedded template if file not found
            template = self._get_embedded_html_template()
        
        # Prepare data for template
        summary_stats = self._generate_summary_stats(analysis_results)
        
        # Replace template variables
        html_content = template.replace('{{GENERATED_DATE}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        html_content = html_content.replace('{{TOTAL_URLS}}', str(len(analysis_results)))
        html_content = html_content.replace('{{SUCCESSFUL_SCANS}}', str(summary_stats['successful_scans']))
        html_content = html_content.replace('{{AVERAGE_SCORE}}', f"{summary_stats['average_score']:.1f}")
        html_content = html_content.replace('{{RESULTS_JSON}}', json.dumps(analysis_results, indent=2))
        
        return html_content
    
    def _generate_summary_stats(self, analysis_results: List[Dict]) -> Dict:
        """Generate summary statistics for reports."""
        successful_results = [r for r in analysis_results if r.get('scan_successful', False)]
        
        if not successful_results:
            return {
                'successful_scans': 0,
                'average_score': 0,
                'grade_distribution': {},
                'common_missing_headers': [],
                'average_response_time': 0
            }
        
        # Calculate statistics
        total_score = sum(r.get('score', 0) for r in successful_results)
        average_score = total_score / len(successful_results)
        
        grade_distribution = {}
        missing_headers = {}
        response_times = []
        
        for result in successful_results:
            # Grade distribution
            grade = result.get('grade', 'F')
            grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
            
            # Missing headers
            summary = result.get('security_summary', {})
            for missing_list in ['critical_missing', 'high_missing', 'medium_missing']:
                for header in summary.get(missing_list, []):
                    missing_headers[header] = missing_headers.get(header, 0) + 1
            
            # Response times
            if result.get('response_time'):
                response_times.append(result['response_time'])
        
        # Most common missing headers
        common_missing = sorted(missing_headers.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'successful_scans': len(successful_results),
            'average_score': average_score,
            'grade_distribution': grade_distribution,
            'common_missing_headers': [{'header': h, 'count': c} for h, c in common_missing],
            'average_response_time': sum(response_times) / len(response_times) if response_times else 0
        }
    
    def print_progress(self, current: int, total: int, url: str, success: bool):
        """Print progress indicator for batch scans."""
        progress_percent = (current / total) * 100
        status_icon = "✅" if success else "❌"
        
        # Create progress bar
        bar_length = 30
        filled_length = int(bar_length * current / total)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        
        progress_text = (f"\r{status_icon} [{bar}] {progress_percent:.1f}% "
                        f"({current}/{total}) - {url[:50]}...")
        
        print(progress_text, end='', flush=True)
        
        if current == total:
            print()  # New line when complete
    
    def save_report(self, content: str, file_path: str, format_type: str):
        """
        Save report to file.
        
        Args:
            content: Report content
            file_path: Output file path
            format_type: Report format (console, json, html)
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"Report saved to: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save {format_type} report: {e}")
            print(f"❌ Failed to save report: {e}")
    
    # Helper methods for formatting
    def _color_text(self, text: str, color: str = '', style: str = '') -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_colors:
            return text
        return f"{style}{color}{text}{Style.RESET_ALL}"
    
    def _format_header(self, text: str) -> str:
        """Format a section header."""
        separator = "=" * len(text)
        return self._color_text(f"{separator}\n{text}\n{separator}", Fore.BLUE, Style.BRIGHT)
    
    def _format_score(self, score: float) -> str:
        """Format a security score with color."""
        if score >= 90:
            color = Fore.GREEN
        elif score >= 70:
            color = Fore.YELLOW
        else:
            color = Fore.RED
        
        return self._color_text(f"{score:.1f}", color, Style.BRIGHT)
    
    def _format_grade(self, grade: str) -> str:
        """Format a security grade with color."""
        color = self._get_grade_color(grade)
        return self._color_text(grade, color, Style.BRIGHT)
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for a security grade."""
        grade_colors = {
            'A': Fore.GREEN,
            'B': Fore.CYAN,
            'C': Fore.YELLOW,
            'D': Fore.MAGENTA,
            'F': Fore.RED
        }
        return grade_colors.get(grade, Fore.WHITE)
    
    def _get_quality_indicator(self, quality: str) -> str:
        """Get emoji indicator for header quality."""
        quality_indicators = {
            'excellent': '🟢',
            'good': '🟡',
            'acceptable': '🟡',
            'basic': '🟠',
            'weak': '🟠',
            'poor': '🔴',
            'dangerous': '🔴',
            'present': '🟡'
        }
        return quality_indicators.get(quality, '⚪')
    
    def _get_embedded_html_template(self) -> str:
        """Return embedded HTML template as fallback."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Headers Analysis Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; }
        .grade-a { color: #28a745; } .grade-b { color: #17a2b8; } .grade-c { color: #ffc107; } .grade-d { color: #fd7e14; } .grade-f { color: #dc3545; }
        .results { margin-top: 30px; }
        pre { background: #f8f9fa; padding: 20px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Headers Analysis Report</h1>
            <p>Generated on {{GENERATED_DATE}}</p>
        </div>
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <h3>Total URLs</h3>
                    <div style="font-size: 2em; font-weight: bold;">{{TOTAL_URLS}}</div>
                </div>
                <div class="stat-card">
                    <h3>Successful Scans</h3>
                    <div style="font-size: 2em; font-weight: bold;">{{SUCCESSFUL_SCANS}}</div>
                </div>
                <div class="stat-card">
                    <h3>Average Score</h3>
                    <div style="font-size: 2em; font-weight: bold;">{{AVERAGE_SCORE}}</div>
                </div>
            </div>
            <div class="results">
                <h2>Detailed Results</h2>
                <pre id="results">{{RESULTS_JSON}}</pre>
            </div>
        </div>
    </div>
</body>
</html>"""