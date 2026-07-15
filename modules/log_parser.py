import re
from datetime import datetime

def parse_log_file(filepath):
    logs = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()
    for line in lines:
        if not line.strip():
            continue
        log_entry = {}
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        log_entry['source_ip'] = ip_match.group() if ip_match else 'Unknown'
        time_match = re.search(r'\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}', line)
        log_entry['timestamp'] = time_match.group() if time_match else str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        line_lower = line.lower()
        if any(w in line_lower for w in ['error', 'failed', 'critical', 'attack', 'breach']):
            log_entry['severity'] = 'High'
        elif any(w in line_lower for w in ['warning', 'warn', 'invalid', 'denied']):
            log_entry['severity'] = 'Medium'
        else:
            log_entry['severity'] = 'Low'
        if any(w in line_lower for w in ['ssh', 'login', 'auth', 'password', 'user']):
            log_entry['event_type'] = 'Authentication'
        elif any(w in line_lower for w in ['http', 'get', 'post', 'request', 'response']):
            log_entry['event_type'] = 'Web Access'
        elif any(w in line_lower for w in ['error', 'exception', 'crash', 'fatal']):
            log_entry['event_type'] = 'System Error'
        else:
            log_entry['event_type'] = 'General'
        log_entry['message'] = line.strip()
        logs.append(log_entry)
    return logs