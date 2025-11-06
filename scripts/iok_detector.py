#!/usr/bin/env python3
"""
IOK Detection Engine - Runs IOK/Sigma rules against collected events
"""

import json
import yaml
import sys
import re
import os
from pathlib import Path

class IOKDetectionEngine:
    def __init__(self, rules_dir):
        self.rules = []
        self.load_rules(rules_dir)
    
    def load_rules(self, rules_dir):
        """Load all IOK/Sigma YAML rules from directory"""
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            print(f"[-] Rules directory not found: {rules_dir}")
            return
        
        for rule_file in rules_path.rglob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    if rule and 'detection' in rule:
                        rule['_file'] = str(rule_file)
                        self.rules.append(rule)
            except Exception as e:
                print(f"[!] Error loading {rule_file}: {e}")
        
        print(f"[+] Loaded {len(self.rules)} IOK rules")
    
    def match_condition(self, event, condition_name, detection):
        """Check if a detection condition matches the event"""
        
        if condition_name not in detection:
            return False
        
        condition = detection[condition_name]
        
        # Handle different condition types
        if isinstance(condition, dict):
            # All conditions must match (AND logic)
            for field, patterns in condition.items():
                if not self.match_field(event, field, patterns):
                    return False
            return True
        
        return False
    
    def match_field(self, event, field, patterns):
        """Check if field in event matches the patterns"""
        
        # Get the field value from event
        field_value = event.get(field, None)
        
        if field_value is None:
            return False
        
        # Convert to list if string
        if isinstance(field_value, str):
            field_values = [field_value]
        elif isinstance(field_value, list):
            field_values = field_value
        else:
            return False
        
        # Normalize patterns to list
        if not isinstance(patterns, list):
            patterns = [patterns]
        
        # Check if any pattern matches any field value
        for pattern in patterns:
            for value in field_values:
                if self.match_pattern(str(value), str(pattern)):
                    return True
        
        return False
    
    def match_pattern(self, text, pattern):
        """Match a pattern against text (supports wildcards and contains)"""
        
        # Handle 'contains' logic
        if '|contains' in pattern or isinstance(pattern, str):
            # Simple substring match
            pattern_clean = pattern.replace('|contains', '').strip()
            if pattern_clean.lower() in text.lower():
                return True
        
        # Handle wildcards
        if '*' in pattern:
            regex_pattern = pattern.replace('*', '.*')
            if re.search(regex_pattern, text, re.IGNORECASE):
                return True
        
        # Exact match
        if pattern.lower() in text.lower():
            return True
        
        return False
    
    def evaluate_condition(self, event, condition_str, detection):
        """Evaluate the condition string logic (AND, OR, NOT)"""
        
        # Simple condition evaluation
        # For PoC, support: "selection", "1 of them", "all of them"
        
        if condition_str == "selection":
            return self.match_condition(event, "selection", detection)
        
        if "1 of them" in condition_str or "1 of selection" in condition_str:
            # At least one selection must match
            for key in detection.keys():
                if key.startswith("selection") and self.match_condition(event, key, detection):
                    return True
            return False
        
        if "all of them" in condition_str:
            # All selections must match
            for key in detection.keys():
                if key.startswith("selection"):
                    if not self.match_condition(event, key, detection):
                        return False
            return True
        
        # Default: try to match as selection name
        return self.match_condition(event, condition_str, detection)
    
    def scan(self, event):
        """Scan an event against all loaded rules"""
        
        detections = []
        
        for rule in self.rules:
            try:
                detection = rule.get('detection', {})
                condition = detection.get('condition', 'selection')
                
                if self.evaluate_condition(event, condition, detection):
                    detections.append({
                        'rule_id': rule.get('id', 'unknown'),
                        'title': rule.get('title', 'Unknown'),
                        'description': rule.get('description', ''),
                        'level': rule.get('level', 'medium'),
                        'tags': rule.get('tags', []),
                        'file': rule.get('_file', '')
                    })
            
            except Exception as e:
                print(f"[!] Error evaluating rule {rule.get('title', 'unknown')}: {e}")
        
        return detections


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 iok_detector.py <event.json> <rules_directory>")
        print("Example: python3 iok_detector.py iok_event.json ./IOK/indicators/")
        sys.exit(1)
    
    event_file = sys.argv[1]
    rules_dir = sys.argv[2]
    
    # Load event
    print(f"[+] Loading event from: {event_file}")
    with open(event_file, 'r', encoding='utf-8') as f:
        event = json.load(f)
    
    # Initialize detection engine
    engine = IOKDetectionEngine(rules_dir)
    
    # Scan event
    print(f"[+] Scanning event against {len(engine.rules)} rules...")
    detections = engine.scan(event)
    
    # Display results
    if detections:
        print(f"\n[!] DETECTED {len(detections)} MATCHES:")
        print("=" * 80)
        
        for det in detections:
            print(f"\nTitle: {det['title']}")
            print(f"Level: {det['level'].upper()}")
            print(f"Description: {det['description']}")
            print(f"Tags: {', '.join(det['tags'])}")
            print(f"Rule: {det['file']}")
            print("-" * 80)
        
        # Save detections
        output_file = event_file.replace('.json', '_detections.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(detections, f, indent=2)
        
        print(f"\n[+] Detections saved to: {output_file}")
    else:
        print("\n[✓] No threats detected")


if __name__ == "__main__":
    main()
