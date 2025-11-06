#!/usr/bin/env python3
"""
Splunk Alert Action for IOK Analysis

Installation:
1. Copy to $SPLUNK_HOME/bin/scripts/iok_enrich.py
2. Make executable: chmod +x iok_enrich.py
3. Configure alert action in Splunk

Usage in Splunk alert:
| script iok_enrich.py url=$url$
"""

import sys
import json
import requests
import csv
import time

# Configuration
IOK_API_URL = "http://localhost:5000"  # Change to your IOK API server
TIMEOUT = 90


def analyze_url(url, iok_api_url):
    """Send URL to IOK API for analysis"""
    
    try:
        response = requests.post(
            f"{iok_api_url}/analyze",
            json={"url": url, "async": False},
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                'success': False,
                'error': f'API returned status {response.status_code}'
            }
    
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': 'Analysis timeout'
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def main():
    """Main Splunk script execution"""
    
    # Read arguments (url is passed via Splunk)
    if len(sys.argv) < 2:
        print("ERROR: No URL provided", file=sys.stderr)
        sys.exit(1)
    
    # Parse url argument (format: url=https://...)
    url_arg = sys.argv[1]
    if not url_arg.startswith('url='):
        print("ERROR: Invalid argument format. Expected url=<URL>", file=sys.stderr)
        sys.exit(1)
    
    url = url_arg[4:]  # Remove 'url=' prefix
    
    # Analyze URL via IOK API
    result = analyze_url(url, IOK_API_URL)
    
    # Output results as CSV for Splunk to ingest
    # Splunk will add these fields to the event
    
    if result.get('success'):
        # Create enriched event
        output = {
            'iok_analyzed': 'true',
            'iok_detection_count': result.get('detection_count', 0),
            'iok_threat_level': result.get('threat_level', 'none'),
            'iok_hostname': result.get('hostname', ''),
            'iok_js_count': result.get('js_count', 0),
            'iok_requests_count': result.get('requests_count', 0),
            'iok_analysis_time': result.get('analysis_time', 0)
        }
        
        # Add detection details if any
        detections = result.get('detections', [])
        if detections:
            # Create multi-value field with detection titles
            detection_titles = [d.get('title', '') for d in detections]
            output['iok_detections'] = '|'.join(detection_titles)
            
            # Get highest severity
            levels = [d.get('level', 'low') for d in detections]
            output['iok_severity'] = max(levels, key=lambda x: 
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x, 0))
        
        # Write CSV output for Splunk
        writer = csv.DictWriter(sys.stdout, fieldnames=output.keys())
        writer.writeheader()
        writer.writerow(output)
    
    else:
        # Analysis failed
        output = {
            'iok_analyzed': 'false',
            'iok_error': result.get('error', 'Unknown error')
        }
        
        writer = csv.DictWriter(sys.stdout, fieldnames=output.keys())
        writer.writeheader()
        writer.writerow(output)


if __name__ == "__main__":
    main()
