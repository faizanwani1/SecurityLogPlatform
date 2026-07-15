def create_incident_from_alert(alert):
    return {
        'title': f"[{alert['severity'].upper()}] {alert['alert_type']} Detected",
        'description': alert['description'],
        'severity': alert['severity'],
        'status': 'open',
        'assigned_to': 'analyst'
    }
