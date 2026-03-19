#!/usr/bin/env python3
"""
IOK API Server - REST API for IOK analysis
Receives URLs, runs IOK collector and detector, returns results
"""

from flask import Flask, request, jsonify
import subprocess
import json
import os
import hashlib
import time
from pathlib import Path
from datetime import datetime
import threading
import queue

app = Flask(__name__)

# Configuration
IOK_COLLECTOR = os.getenv('IOK_COLLECTOR', './iok_collector.py')
IOK_DETECTOR = os.getenv('IOK_DETECTOR', './iok_detector.py')
IOK_RULES = os.getenv('IOK_RULES', './IOK/indicators/')
WORK_DIR = os.getenv('IOK_WORK_DIR', '/tmp/iok_analysis')
MAX_WORKERS = int(os.getenv('IOK_MAX_WORKERS', '3'))
ANALYSIS_TIMEOUT = int(os.getenv('IOK_TIMEOUT', '60'))

# Create work directory
Path(WORK_DIR).mkdir(parents=True, exist_ok=True)

# Analysis queue for rate limiting
analysis_queue = queue.Queue()
results_cache = {}


def worker():
    """Background worker that processes analysis requests"""
    while True:
        try:
            job = analysis_queue.get(timeout=1)
            if job is None:
                break
            
            url, job_id = job
            results_cache[job_id] = {'status': 'processing', 'started': time.time()}
            
            try:
                result = analyze_url(url, job_id)
                results_cache[job_id] = {
                    'status': 'complete',
                    'result': result,
                    'completed': time.time()
                }
            except Exception as e:
                results_cache[job_id] = {
                    'status': 'error',
                    'error': str(e),
                    'completed': time.time()
                }
            
            analysis_queue.task_done()
            
        except queue.Empty:
            continue


def analyze_url(url, job_id):
    """Run IOK analysis on a URL"""
    
    # Generate filenames
    event_file = f"{WORK_DIR}/{job_id}_event.json"
    det_file = f"{WORK_DIR}/{job_id}_event_detections.json"
    
    start_time = time.time()
    
    # Step 1: Collect IOK event data
    try:
        collect_result = subprocess.run(
            ['python3', IOK_COLLECTOR, url, event_file],
            capture_output=True,
            text=True,
            timeout=ANALYSIS_TIMEOUT
        )
        
        if collect_result.returncode != 0:
            return {
                'success': False,
                'error': 'Collection failed',
                'details': collect_result.stderr,
                'analysis_time': time.time() - start_time
            }
    
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Collection timeout',
            'analysis_time': time.time() - start_time
        }
    
    # Step 2: Run IOK detection
    try:
        detect_result = subprocess.run(
            ['python3', IOK_DETECTOR, event_file, IOK_RULES],
            capture_output=True,
            text=True,
            timeout=30
        )
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Detection timeout',
            'analysis_time': time.time() - start_time
        }
    
    # Step 3: Load results
    detections = []
    if os.path.exists(det_file):
        with open(det_file, 'r') as f:
            detections = json.load(f)
    
    # Load event data for context
    event_data = {}
    if os.path.exists(event_file):
        with open(event_file, 'r') as f:
            event_data = json.load(f)
    
    # Clean up files (optional - comment out for debugging)
    # os.remove(event_file)
    # if os.path.exists(det_file):
    #     os.remove(det_file)
    
    return {
        'success': True,
        'url': url,
        'detections': detections,
        'detection_count': len(detections),
        'threat_level': max([d.get('level', 'low') for d in detections], default='none'),
        'hostname': event_data.get('hostname', ''),
        'title': event_data.get('title', []),
        'js_count': len(event_data.get('js', [])),
        'requests_count': len(event_data.get('requests', [])),
        'analysis_time': time.time() - start_time,
        'timestamp': datetime.now().isoformat()
    }


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'queue_size': analysis_queue.qsize(),
        'cache_size': len(results_cache)
    })


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze a URL for phishing indicators
    
    POST /analyze
    {
        "url": "https://suspicious-site.com",
        "async": true  # Optional, default false
    }
    """
    
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url parameter'}), 400
    
    url = data['url']
    async_mode = data.get('async', False)
    
    # Generate job ID
    job_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()
    
    if async_mode:
        # Queue for background processing
        analysis_queue.put((url, job_id))
        return jsonify({
            'job_id': job_id,
            'status': 'queued',
            'message': 'Analysis queued. Check /status/{job_id} for results'
        }), 202
    
    else:
        # Synchronous analysis
        try:
            result = analyze_url(url, job_id)
            return jsonify(result)
        
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


@app.route('/status/<job_id>', methods=['GET'])
def status(job_id):
    """Check status of async analysis job"""
    
    if job_id not in results_cache:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(results_cache[job_id])


@app.route('/batch', methods=['POST'])
def batch():
    """
    Batch analyze multiple URLs
    
    POST /batch
    {
        "urls": ["https://site1.com", "https://site2.com"]
    }
    """
    
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({'error': 'Missing urls parameter'}), 400
    
    urls = data['urls']
    
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({'error': 'urls must be a non-empty array'}), 400
    
    if len(urls) > 10:
        return jsonify({'error': 'Maximum 10 URLs per batch request'}), 400
    
    # Queue all URLs
    job_ids = []
    for url in urls:
        job_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()
        analysis_queue.put((url, job_id))
        job_ids.append({'url': url, 'job_id': job_id})
    
    return jsonify({
        'jobs': job_ids,
        'message': 'Batch analysis queued'
    }), 202


@app.route('/rules/stats', methods=['GET'])
def rules_stats():
    """Get statistics about loaded IOK rules"""
    
    try:
        # Count rule files
        rule_count = len(list(Path(IOK_RULES).rglob("*.yml")))
        
        return jsonify({
            'rules_directory': IOK_RULES,
            'rule_count': rule_count
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def init_workers():
    """Initialize background worker threads"""
    for i in range(MAX_WORKERS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()


if __name__ == '__main__':
    print("[+] Starting IOK API Server")
    print(f"[+] IOK Collector: {IOK_COLLECTOR}")
    print(f"[+] IOK Detector: {IOK_DETECTOR}")
    print(f"[+] IOK Rules: {IOK_RULES}")
    print(f"[+] Work Directory: {WORK_DIR}")
    print(f"[+] Max Workers: {MAX_WORKERS}")
    
    # Start background workers
    init_workers()
    
    # Start Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
