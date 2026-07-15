// Auto-dismiss alerts after 4 seconds
setTimeout(function() {
    var alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        alert.style.transition = 'opacity 0.5s';
        alert.style.opacity = '0';
        setTimeout(function() { alert.remove(); }, 500);
    });
}, 4000);

// Confirm before deleting
function confirmDelete(message) {
    return confirm(message || 'Are you sure you want to delete this?');
}

// Severity badge color helper
function getSeverityClass(severity) {
    const map = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low'
    };
    return map[severity] || 'badge-secondary';
}