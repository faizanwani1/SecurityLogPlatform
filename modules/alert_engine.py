from collections import Counter

def run_alert_rules(logs):
    alerts = []
    ip_failures = Counter()
    ip_log_ids = {}

    for log in logs:
        msg = log.get('message', '').lower()
        ip = log.get('ip_address', 'unknown')
        log_id = log.get('id')

        if any(w in msg for w in ['failed password', 'authentication failure', 'invalid user']):
            ip_failures[ip] += 1
            ip_log_ids[ip] = log_id

        if 'root' in msg and 'accepted' in msg:
            alerts.append({
                'alert_type': 'Root Login',
                'description': f'Root login accepted from {ip}',
                'severity': 'high',
                'log_id': log_id
            })

        if 'sudo' in msg and 'error' in msg.lower():
            alerts.append({
                'alert_type': 'Sudo Abuse',
                'description': f'Suspicious sudo usage detected: {msg[:80]}',
                'severity': 'medium',
                'log_id': log_id
            })

    for ip, count in ip_failures.items():
        if count >= 3:
            alerts.append({
                'alert_type': 'Brute Force',
                'description': f'{count} failed login attempts from IP {ip}',
                'severity': 'critical',
                'log_id': ip_log_ids.get(ip)
            })

    return alerts