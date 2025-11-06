#!/usr/bin/env python3
"""
Elastic Stack IOK Enrichment Script

Can be used in multiple ways:
1. Called from Elasticsearch Watcher
2. Called from Logstash pipeline (exec filter)
3. Standalone enrichment of ES documents

Usage:
  python3 elastic_iok_enrich.py --url <URL>
  python3 elastic_iok_enrich.py --es-query "proxy.url:*phishing*"
"""

import argparse
import json
import sys
import requests
from elasticsearch import Elasticsearch
from datetime import datetime

# Configuration
IOK_API_URL = "http://localhost:5000"
ES_HOST = "localhost:9200"
ES_INDEX = "iok-detections"
ES_USER = None  # Set if authentication required
ES_PASSWORD = None


def analyze_url(url):
    """Send URL to IOK API for analysis"""
    
    try:
        response = requests.post(
            f"{IOK_API_URL}/analyze",
            json={"url": url, "async": False},
            timeout=90
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return None
    
    except Exception as e:
        print(f"Error analyzing URL: {e}", file=sys.stderr)
        return None


def index_to_elasticsearch(es, url, result):
    """Index IOK detection result to Elasticsearch"""
    
    doc = {
        '@timestamp': datetime.now().isoformat(),
        'url': url,
        'iok': {
            'success': result.get('success', False),
            'detection_count': result.get('detection_count', 0),
            'threat_level': result.get('threat_level', 'none'),
            'hostname': result.get('hostname', ''),
            'title': result.get('title', []),
            'js_count': result.get('js_count', 0),
            'requests_count': result.get('requests_count', 0),
            'analysis_time': result.get('analysis_time', 0),
            'detections': result.get('detections', [])
        }
    }
    
    try:
        es.index(index=ES_INDEX, document=doc)
        return True
    except Exception as e:
        print(f"Error indexing to ES: {e}", file=sys.stderr)
        return False


def process_url(url, es=None, output_json=False):
    """Process a single URL and optionally index to ES"""
    
    result = analyze_url(url)
    
    if not result:
        print(f"Failed to analyze: {url}", file=sys.stderr)
        return None
    
    # Index to Elasticsearch if connection provided
    if es and result.get('success'):
        index_to_elasticsearch(es, url, result)
    
    # Output results
    if output_json:
        print(json.dumps(result, indent=2))
    else:
        if result.get('success'):
            det_count = result.get('detection_count', 0)
            if det_count > 0:
                print(f"[!] THREAT DETECTED: {url}")
                print(f"    Detections: {det_count}")
                print(f"    Threat Level: {result.get('threat_level', 'unknown')}")
                for det in result.get('detections', []):
                    print(f"    - {det.get('title')} [{det.get('level')}]")
            else:
                print(f"[✓] Clean: {url}")
        else:
            print(f"[-] Analysis failed: {url}")
    
    return result


def query_and_enrich(es, query):
    """Query ES for suspicious URLs and enrich them with IOK"""
    
    try:
        # Search for documents
        resp = es.search(
            index="proxy-*",  # Adjust to your index pattern
            body={
                "query": {
                    "query_string": {
                        "query": query
                    }
                },
                "size": 100
            }
        )
        
        hits = resp['hits']['hits']
        print(f"[+] Found {len(hits)} documents to enrich")
        
        for hit in hits:
            url = hit['_source'].get('url') or hit['_source'].get('proxy', {}).get('url')
            if url:
                print(f"[+] Analyzing: {url}")
                process_url(url, es=es)
        
    except Exception as e:
        print(f"Error querying ES: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='IOK Enrichment for Elastic Stack')
    parser.add_argument('--url', help='Single URL to analyze')
    parser.add_argument('--es-query', help='Query ES and enrich matching documents')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--es-host', default=ES_HOST, help='Elasticsearch host')
    parser.add_argument('--es-index', default=ES_INDEX, help='Index for IOK detections')
    
    args = parser.parse_args()
    
    # Initialize ES connection if needed
    es = None
    if args.es_query or args.es_host != ES_HOST:
        try:
            es = Elasticsearch(
                [args.es_host],
                basic_auth=(ES_USER, ES_PASSWORD) if ES_USER else None
            )
        except Exception as e:
            print(f"Error connecting to ES: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Process based on mode
    if args.url:
        # Single URL mode
        process_url(args.url, es=es, output_json=args.json)
    
    elif args.es_query:
        # Query and enrich mode
        if not es:
            print("Error: ES connection required for query mode", file=sys.stderr)
            sys.exit(1)
        query_and_enrich(es, args.es_query)
    
    else:
        # Read URLs from stdin
        for line in sys.stdin:
            url = line.strip()
            if url:
                process_url(url, es=es, output_json=args.json)


if __name__ == "__main__":
    main()
