#!/usr/bin/env python3
"""
MCP Server for IP and Domain Analysis using iprep
"""

import json
import logging
import os
import sys
from typing import List
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

# Add iprep to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'iprep'))

from mcp.server.fastmcp import FastMCP

from iprep.agent import IPRepAgent
from iprep.config import SecureConfig
from iprep.validator import InputValidator
from iprep.plugins.domain_content.whois_analyser import WHOISAnalyserPlugin
from iprep.plugins.domain_content.tls_analyser import TLSAnalyserPlugin

# Configure logging to stderr only (not stdout which MCP uses)
logging.basicConfig(
    level=logging.WARNING,  # Reduced logging to avoid interference
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

def suppress_iprep_output(func_call):
    """Context manager to suppress iprep print statements that interfere with MCP protocol."""
    stdout_capture = StringIO()
    stderr_capture = StringIO()
    
    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            result = func_call()
        
        # Log any captured output to stderr for debugging if needed
        captured_stdout = stdout_capture.getvalue()
        captured_stderr = stderr_capture.getvalue()
        
        if captured_stdout and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Captured stdout: {captured_stdout}")
        if captured_stderr and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Captured stderr: {captured_stderr}")
            
        return result
    except Exception as e:
        # Log the exception to stderr
        logger.error(f"Error in function call: {str(e)}")
        raise

# Ensure iprep debug mode is disabled to prevent stdout interference
os.environ['IPREP_DEBUG'] = 'false'

# Create the MCP server
mcp = FastMCP("iprep-mcp")

@mcp.tool()
def analyze_ip(ip: str, mode: str = "passive") -> str:
    """
    Analyze an IP address for reputation and geolocation information.
    
    Args:
        ip: The IP address to analyze
        mode: Analysis mode - "passive" (default) or "active"
    
    Returns:
        JSON string containing analysis results
    """
    try:
        # Set active mode via environment variable
        if mode == "active":
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        else:
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'false'
        
        # Validate IP address
        validator = InputValidator()
        if not validator.is_valid_ip(ip):
            return json.dumps({"error": "Invalid IP address format"})
        
        # Create agent and run analysis with output suppression
        def run_analysis():
            agent = IPRepAgent()
            return agent.analyze_ip(ip)
        
        results = suppress_iprep_output(run_analysis)
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"Error analyzing IP: {str(e)}")
        return json.dumps({"error": "Analysis failed"})

@mcp.tool()
def analyze_domain(domain: str, mode: str = "passive") -> str:
    """
    Analyze a domain for reputation and content information.
    
    Note: For detailed domain registration information, consider using the 'whois_lookup' tool first,
    as it provides comprehensive domain ownership and administrative details.
    
    Args:
        domain: The domain to analyze
        mode: Analysis mode - "passive" (default) or "active"
    
    Returns:
        JSON string containing analysis results
    """
    try:
        # Set active mode via environment variable
        if mode == "active":
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        else:
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'false'
        
        # Validate domain
        validator = InputValidator()
        if not validator.is_valid_domain(domain):
            return json.dumps({"error": "Invalid domain format"})
        
        # Create agent and run analysis with output suppression
        def run_analysis():
            agent = IPRepAgent()
            return agent.analyze_domain(domain)
        
        results = suppress_iprep_output(run_analysis)
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"Error analyzing domain: {str(e)}")
        return json.dumps({"error": "Analysis failed"})

@mcp.tool()
def whois_lookup(domain: str) -> str:
    """
    Perform a WHOIS lookup to get comprehensive domain registration information.
    
    This tool provides detailed domain ownership, administrative contacts, nameservers,
    registration dates, and other authoritative domain information. Use this tool
    when you need specific domain registration details.
    
    Args:
        domain: The domain name to look up (e.g., "example.com")
    
    Returns:
        JSON string containing WHOIS data including registrar, contacts, dates, and nameservers
    """
    try:
        # Enable active plugins for WHOIS (it requires direct server contact)
        os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        
        # Validate domain
        validator = InputValidator()
        if not validator.is_valid_domain(domain):
            return json.dumps({"error": "Invalid domain format"})
        
        def run_whois():
            whois_plugin = WHOISAnalyserPlugin()
            return whois_plugin.analyze_domain_content(domain)
        
        results = suppress_iprep_output(run_whois)
        
        if results is None:
            return json.dumps({"error": "WHOIS lookup failed or no data available"})
        
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"Error in WHOIS lookup: {str(e)}")
        return json.dumps({"error": "WHOIS lookup failed"})

@mcp.tool()
def tls_analysis(domain: str, port: int = 443) -> str:
    """
    Analyze TLS/SSL certificate and security configuration for a domain.
    
    This tool examines the SSL/TLS certificate, cipher suites, and security
    configuration by connecting directly to the target domain.
    
    Args:
        domain: The domain name to analyze (e.g., "example.com")
        port: The port to connect to (default: 443 for HTTPS)
    
    Returns:
        JSON string containing TLS certificate details, validity, and security configuration
    """
    try:
        # Enable active plugins for TLS analysis (it requires direct connection)
        os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        
        # Validate domain
        validator = InputValidator()
        if not validator.is_valid_domain(domain):
            return json.dumps({"error": "Invalid domain format"})
        
        def run_tls_analysis():
            tls_plugin = TLSAnalyserPlugin()
            # Note: The TLS plugin doesn't directly support port parameter in current implementation
            # but we include it in the interface for future enhancement
            return tls_plugin.analyze_domain_content(domain)
        
        results = suppress_iprep_output(run_tls_analysis)
        
        if results is None:
            return json.dumps({"error": "TLS analysis failed or no certificate available"})
        
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"Error in TLS analysis: {str(e)}")
        return json.dumps({"error": "TLS analysis failed"})

@mcp.tool()
def batch_analyze(targets: List[str], mode: str = "passive") -> str:
    """
    Analyze multiple IPs and/or domains in a single request.
    
    Note: For domains requiring detailed registration information, consider using
    'whois_lookup' individually for each domain to get comprehensive WHOIS data.
    
    Args:
        targets: List of IP addresses and/or domains to analyze
        mode: Analysis mode - "passive" (default) or "active"
    
    Returns:
        JSON string containing analysis results for all targets
    """
    try:
        # Set active mode via environment variable
        if mode == "active":
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        else:
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'false'
        
        def run_batch_analysis():
            agent = IPRepAgent()
            validator = InputValidator()
            
            results = {}
            for target in targets:
                target = target.strip()
                try:
                    if validator.is_valid_ip(target):
                        results[target] = agent.analyze_ip(target)
                    elif validator.is_valid_domain(target):
                        results[target] = agent.analyze_domain(target)
                    else:
                        results[target] = {"error": "Invalid target format"}
                except Exception as e:
                    # Log individual target errors
                    results[target] = {"error": f"Analysis failed: {str(e)}"}
            return results
        
        results = suppress_iprep_output(run_batch_analysis)
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}")
        return json.dumps({"error": "Analysis failed"})

@mcp.tool()
def get_analysis_config() -> str:
    """
    Get current analysis configuration and available plugins.
    
    Returns:
        JSON string containing configuration details
    """
    try:
        def get_config_info():
            config = SecureConfig()
            agent = IPRepAgent()
            
            return {
                "active_plugins_allowed": config.allow_active_plugins(),
                "passive_only_mode": config.get_passive_only_mode(),
                "available_plugins": {
                    "ip_plugins": [p.__class__.__name__ for p in agent.plugins],
                    "domain_reputation_plugins": [p.__class__.__name__ for p in agent.domain_reputation_plugins],
                    "domain_content_plugins": [p.__class__.__name__ for p in agent.domain_content_plugins]
                },
                "allowed_traffic_types": config.get_allowed_traffic_types(),
                "debug_mode": config.is_debug_mode()
            }
        
        config_info = suppress_iprep_output(get_config_info)
        return json.dumps(config_info, indent=2)
    except Exception as e:
        logger.error(f"Error getting config: {str(e)}")
        return json.dumps({"error": "Configuration retrieval failed"})

@mcp.tool()
def diagnose_plugins() -> str:
    """
    Diagnostic tool to check plugin loading and configuration status.
    
    Returns:
        JSON string containing detailed plugin and configuration diagnostics
    """
    try:
        def get_diagnostics():
            config = SecureConfig()
            agent = IPRepAgent()
            
            diagnostics = {
                "environment_variables": {
                    "IPREP_DEBUG": os.environ.get('IPREP_DEBUG', 'not set'),
                    "IPREP_ALLOW_ACTIVE_PLUGINS": os.environ.get('IPREP_ALLOW_ACTIVE_PLUGINS', 'not set'),
                    "API_KEYS_PRESENT": {
                        "ABUSEIPDB_API_KEY": bool(os.environ.get('ABUSEIPDB_API_KEY')),
                        "GREYNOISE_API_KEY": bool(os.environ.get('GREYNOISE_API_KEY')),
                        "VIRUSTOTAL_API_KEY": bool(os.environ.get('VIRUSTOTAL_API_KEY')),
                        "URLVOID_API_KEY": bool(os.environ.get('URLVOID_API_KEY')),
                        "IPINFO_API_KEY": bool(os.environ.get('IPINFO_API_KEY'))
                    }
                },
                "loaded_plugins": {
                    "ip_plugins_count": len(agent.plugins),
                    "domain_reputation_plugins_count": len(agent.domain_reputation_plugins),
                    "domain_content_plugins_count": len(agent.domain_content_plugins),
                    "ip_plugin_names": [p.__class__.__name__ for p in agent.plugins],
                    "domain_reputation_plugin_names": [p.__class__.__name__ for p in agent.domain_reputation_plugins],
                    "domain_content_plugin_names": [p.__class__.__name__ for p in agent.domain_content_plugins]
                },
                "config_status": {
                    "active_plugins_allowed": config.allow_active_plugins(),
                    "passive_only_mode": config.get_passive_only_mode(),
                    "debug_mode": config.is_debug_mode(),
                    "allowed_traffic_types": config.get_allowed_traffic_types(),
                    "request_timeout": config.get_request_timeout()
                }
            }
            
            return diagnostics
            
        diagnostics = suppress_iprep_output(get_diagnostics)
        return json.dumps(diagnostics, indent=2)
    except Exception as e:
        logger.error(f"Error getting diagnostics: {str(e)}")
        return json.dumps({"error": "Diagnostics failed"})

if __name__ == "__main__":
    mcp.run()