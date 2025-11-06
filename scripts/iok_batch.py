#!/usr/bin/env python3
"""
IOK Batch Scanner - Process multiple URLs and generate detection report
"""

import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime

def scan_url(url, output_dir):
    """Collect and detect a single URL"""
    
    print(f"\n[+] Processing: {url}")
    
    # Generate filename from URL
    safe_name = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    event_file = output_dir / f"{safe_name}_{timestamp}.json"
    
    # Collect data
    print(f"[*] Collecting event data...")
    try:
        result = subprocess.run(
            ['python3', 'iok_collector.py', url, str(event_file)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"[-] Collection failed: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print(f"[-] Collection timed out")
        return None
    except Exception as e:
        print(f"[-] Collection error: {e}")
        return None
    
    # Run detection
    print(f"[*] Running detections...")
    try:
        result = subprocess.run(
            ['python3', 'iok_detector.py', str(event_file), 'IOK/indicators/'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Load detections
        det_file = str(event_file).replace('.json', '_detections.json')
        if Path(det_file).exists():
            with open(det_file, 'r') as f:
                detections = json.load(f)
            
            return {
                'url': url,
                'event_file': str(event_file),
                'detections': detections,
                'detection_count': len(detections)
            }
        else:
            return {
                'url': url,
                'event_file': str(event_file),
                'detections': [],
                'detection_count': 0
            }
    
    except Exception as e:
        print(f"[-] Detection error: {e}")
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 iok_batch.py <url_list.txt>")
        print("\nFormat of url_list.txt:")
        print("  https://phishing-site1.com")
        print("  https://phishing-site2.com")
        print("  ...")
        sys.exit(1)
    
    url_file = sys.argv[1]
    
    # Read URLs
    print(f"[+] Loading URLs from: {url_file}")
    with open(url_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"[+] Found {len(urls)} URLs to scan")
    
    # Create output directory
    output_dir = Path('batch_results')
    output_dir.mkdir(exist_ok=True)
    
    # Process each URL
    results = []
    for i, url in enumerate(urls, 1):
        print(f"\n{'='*80}")
        print(f"[{i}/{len(urls)}] Scanning: {url}")
        
        result = scan_url(url, output_dir)
        if result:
            results.append(result)
            if result['detection_count'] > 0:
                print(f"[!] {result['detection_count']} detections found")
            else:
                print(f"[✓] No detections")
        
        # Rate limiting
        if i < len(urls):
            time.sleep(2)
    
    # Generate summary report
    print(f"\n{'='*80}")
    print("[+] Batch Scan Complete")
    print(f"{'='*80}")
    
    total_scanned = len(results)
    total_detected = sum(1 for r in results if r['detection_count'] > 0)
    
    print(f"\nSummary:")
    print(f"  URLs Scanned: {total_scanned}")
    print(f"  Threats Detected: {total_detected}")
    print(f"  Clean Sites: {total_scanned - total_detected}")
    
    # Top detections
    all_detections = []
    for result in results:
        for det in result['detections']:
            all_detections.append(det)
    
    if all_detections:
        print(f"\nTop Detection Rules:")
        rule_counts = {}
        for det in all_detections:
            rule = det['title']
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {count}x {rule}")
    
    # Save detailed report
    report_file = output_dir / f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({
            'scan_date': datetime.now().isoformat(),
            'total_urls': len(urls),
            'scanned': total_scanned,
            'detected': total_detected,
            'results': results
        }, f, indent=2)
    
    print(f"\n[+] Detailed report saved: {report_file}")


if __name__ == "__main__":
    main()
