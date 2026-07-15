from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

from config import Config

from database import (
    db,
    User,
    LogEntry,
    Alert,
    Incident,
    UploadedFile
)

from log_parser import parse_log_file
from report_generator import generate_report

from werkzeug.utils import secure_filename

from functools import wraps

from datetime import datetime

import os


# =====================================================
# FLASK APP CONFIGURATION
# =====================================================

app = Flask(__name__)

app.config.from_object(Config)

app.secret_key = app.config['SECRET_KEY']

db.init_app(app)

with app.app_context():
    db.create_all()


# =====================================================
# LOGIN REQUIRED DECORATOR
# =====================================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if 'user' not in session:

            return redirect(
                url_for('login')
            )

        return f(*args, **kwargs)

    return decorated_function


# =====================================================
# LOGIN ROUTE
# =====================================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get('username')

        password = request.form.get('password')

        user = User.query.filter_by(
            username=username,
            password=password
        ).first()

        if user:

            session['user'] = user.username

            session['role'] = user.role

            session['full_name'] = user.full_name

            flash(
                'Login Successful',
                'success'
            )

            return redirect(
                url_for('dashboard')
            )

        else:

            flash(
                'Invalid Username or Password',
                'danger'
            )

    return render_template(
        'login.html'
    )


# =====================================================
# LOGOUT ROUTE
# =====================================================

@app.route('/logout')
def logout():

    session.clear()

    flash(
        'Logged Out Successfully',
        'info'
    )

    return redirect(
        url_for('login')
    )


# =====================================================
# CREATE DEFAULT ADMIN
# RUN ONLY ONCE
# =====================================================

@app.route('/create_admin')
def create_admin():

    existing_user = User.query.filter_by(
        username='admin'
    ).first()

    if existing_user:

        return "Admin already exists"

    admin = User(
        username='admin',
        password='admin123',
        full_name='System Administrator',
        email='admin@seclog.com',
        role='admin'
    )

    db.session.add(admin)

    db.session.commit()

    return "Admin Created Successfully"


# =====================================================
# HOME REDIRECT
# =====================================================

@app.route('/')
def home():

    return redirect(
        url_for('login')
    )
# =====================================================
# DASHBOARD
# =====================================================

@app.route('/dashboard')
@login_required
def dashboard():

    total_logs = LogEntry.query.count()

    total_alerts = Alert.query.count()

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status='Open'
    ).count()

    resolved_incidents = Incident.query.filter_by(
        status='Resolved'
    ).count()

    critical_count = LogEntry.query.filter_by(
        severity='Critical'
    ).count()

    high_count = LogEntry.query.filter_by(
        severity='High'
    ).count()

    medium_count = LogEntry.query.filter_by(
        severity='Medium'
    ).count()

    low_count = LogEntry.query.filter_by(
        severity='Low'
    ).count()

    open_count = Incident.query.filter_by(
        status='Open'
    ).count()

    investigating_count = Incident.query.filter_by(
        status='Investigating'
    ).count()

    progress_count = Incident.query.filter_by(
        status='In Progress'
    ).count()

    resolved_count = Incident.query.filter_by(
        status='Resolved'
    ).count()

    closed_count = Incident.query.filter_by(
        status='Closed'
    ).count()

    recent_alerts = LogEntry.query.order_by(
        LogEntry.id.desc()
    ).limit(10).all()

    return render_template(
        'dashboard.html',

        total_logs=total_logs,
        total_alerts=total_alerts,

        open_incidents=open_incidents,
        resolved_incidents=resolved_incidents,

        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,

        open_count=open_count,
        investigating_count=investigating_count,
        progress_count=progress_count,
        resolved_count=resolved_count,
        closed_count=closed_count,

        recent_alerts=recent_alerts
    )


# =====================================================
# UPLOAD LOG FILE
# =====================================================

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():

    if request.method == 'POST':

        file = request.files.get('logfile')

        log_type = request.form.get(
            'log_type'
        )

        if file:

            filename = secure_filename(
                file.filename
            )

            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                filename
            )

            file.save(filepath)

            uploaded = UploadedFile(
                filename=filename,
                log_type=log_type
            )

            db.session.add(uploaded)

            parsed_logs = parse_log_file(
                filepath
            )

            for entry in parsed_logs:

                log = LogEntry(
                    timestamp=entry['timestamp'],
                    source_ip=entry['source_ip'],
                    event_type=entry['event_type'],
                    severity=entry['severity'],
                    message=entry['message'],
                    filename=filename
                )

                db.session.add(log)

                if entry['severity'] in [
                    'Critical',
                    'High'
                ]:

                    alert = Alert(
                        timestamp=entry['timestamp'],
                        ip_address=entry['source_ip'],
                        event_type=entry['event_type'],
                        severity=entry['severity'],
                        status='Open'
                    )

                    db.session.add(alert)

            db.session.commit()

            flash(
                'Log file uploaded successfully',
                'success'
            )

            return redirect(
                url_for('logs')
            )

    uploaded_files = UploadedFile.query.order_by(
        UploadedFile.id.desc()
    ).all()

    return render_template(
        'upload.html',
        uploaded_files=uploaded_files
    )


# =====================================================
# LOGS PAGE
# =====================================================

@app.route('/logs')
@login_required
def logs():

    logs = LogEntry.query.order_by(
        LogEntry.id.desc()
    ).all()

    total_logs = LogEntry.query.count()

    critical_logs = LogEntry.query.filter_by(
        severity='Critical'
    ).count()

    high_logs = LogEntry.query.filter_by(
        severity='High'
    ).count()

    low_logs = LogEntry.query.filter_by(
        severity='Low'
    ).count()

    return render_template(
        'logs.html',

        logs=logs,

        total_logs=total_logs,

        critical_logs=critical_logs,

        high_logs=high_logs,

        low_logs=low_logs
    )


# =====================================================
# ALERTS PAGE
# =====================================================

@app.route('/alerts')
@login_required
def alerts():

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).all()

    critical_count = Alert.query.filter_by(
        severity='Critical'
    ).count()

    high_count = Alert.query.filter_by(
        severity='High'
    ).count()

    medium_count = Alert.query.filter_by(
        severity='Medium'
    ).count()

    low_count = Alert.query.filter_by(
        severity='Low'
    ).count()

    return render_template(
        'alerts.html',

        alerts=alerts,

        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )
# =====================================================
# CREATE INCIDENT FROM ALERT
# =====================================================

@app.route('/create_incident/<int:alert_id>', methods=['POST'])
@login_required
def create_incident(alert_id):

    alert = Alert.query.get_or_404(alert_id)

    incident = Incident(
        title=f"{alert.event_type} Alert",
        description=f"Security alert generated from IP {alert.ip_address}",
        severity=alert.severity,
        status="Open",
        assigned_to=session.get('full_name', 'Analyst'),
        source_ip=alert.ip_address,
        event_type=alert.event_type
    )

    db.session.add(incident)

    alert.status = "Incident Created"

    db.session.commit()

    flash(
        "Incident created successfully",
        "success"
    )

    return redirect(
        url_for('incidents')
    )


# =====================================================
# INCIDENTS PAGE
# =====================================================

@app.route('/incidents')
@login_required
def incidents():

    incidents = Incident.query.order_by(
        Incident.id.desc()
    ).all()

    open_count = Incident.query.filter_by(
        status='Open'
    ).count()

    investigating_count = Incident.query.filter_by(
        status='Investigating'
    ).count()

    progress_count = Incident.query.filter_by(
        status='In Progress'
    ).count()

    resolved_count = Incident.query.filter_by(
        status='Resolved'
    ).count()

    return render_template(
        'incidents.html',

        incidents=incidents,

        open_count=open_count,
        investigating_count=investigating_count,
        progress_count=progress_count,
        resolved_count=resolved_count
    )


# =====================================================
# INCIDENT DETAIL PAGE
# =====================================================

@app.route('/incident/<int:id>')
@login_required
def incident_detail(id):

    incident = Incident.query.get_or_404(id)

    return render_template(
        'incident_detail.html',
        incident=incident
    )


# =====================================================
# UPDATE INCIDENT
# =====================================================

@app.route(
    '/update_incident/<int:id>',
    methods=['GET', 'POST']
)
@login_required
def update_incident(id):

    incident = Incident.query.get_or_404(id)

    if request.method == 'POST':

        incident.assigned_to = request.form.get(
            'assigned_to'
        )

        incident.status = request.form.get(
            'status'
        )

        incident.investigation_notes = request.form.get(
            'investigation_notes'
        )

        incident.containment = request.form.get(
            'containment'
        )

        incident.remediation = request.form.get(
            'remediation'
        )

        incident.recovery = request.form.get(
            'recovery'
        )

        incident.resolution_notes = request.form.get(
            'resolution'
        )

        incident.lessons_learned = request.form.get(
            'lessons_learned'
        )

        incident.updated_at = datetime.utcnow()

        db.session.commit()

        flash(
            'Incident updated successfully',
            'success'
        )

        return redirect(
            url_for('incident_detail', id=id)
        )

    return render_template(
        'update_incident.html',
        incident=incident
    )


# =====================================================
# CLOSE INCIDENT
# =====================================================

@app.route('/close_incident/<int:id>')
@login_required
def close_incident(id):

    incident = Incident.query.get_or_404(id)

    incident.status = 'Closed'

    incident.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        'Incident closed successfully',
        'success'
    )

    return redirect(
        url_for('incidents')
    )
# =====================================================
# USERS PAGE
# =====================================================

@app.route('/users')
@login_required
def users():

    if session.get('role') != 'admin':

        flash(
            'Access Denied',
            'danger'
        )

        return redirect(
            url_for('dashboard')
        )

    users = User.query.order_by(
        User.id.desc()
    ).all()

    total_users = User.query.count()

    active_users = User.query.filter_by(
        status='Active'
    ).count()

    admin_users = User.query.filter_by(
        role='admin'
    ).count()

    return render_template(
        'users.html',

        users=users,

        total_users=total_users,

        active_users=active_users,

        admin_users=admin_users
    )


# =====================================================
# ADD USER
# =====================================================

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():

    if session.get('role') != 'admin':

        return redirect(
            url_for('dashboard')
        )

    user = User(

        username=request.form.get(
            'username'
        ),

        password=request.form.get(
            'password'
        ),

        email=request.form.get(
            'email'
        ),

        full_name=request.form.get(
            'username'
        ),

        role=request.form.get(
            'role'
        ),

        status='Active'
    )

    db.session.add(user)

    db.session.commit()

    flash(
        'User Added Successfully',
        'success'
    )

    return redirect(
        url_for('users')
    )


# =====================================================
# DELETE USER
# =====================================================

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):

    if session.get('role') != 'admin':

        return redirect(
            url_for('dashboard')
        )

    user = User.query.get_or_404(id)

    db.session.delete(user)

    db.session.commit()

    flash(
        'User Deleted Successfully',
        'success'
    )

    return redirect(
        url_for('users')
    )


# =====================================================
# REPORT PAGE
# =====================================================

@app.route('/report')
@login_required
def report():

    incidents = Incident.query.order_by(
        Incident.id.desc()
    ).all()

    logs = LogEntry.query.order_by(
        LogEntry.id.desc()
    ).all()

    return render_template(
        'report.html',

        incidents=incidents,

        logs=logs
    )


# =====================================================
# GENERATE PDF REPORT
# =====================================================

@app.route('/generate_report')
@login_required
def generate_report_route():

    incidents = Incident.query.all()

    logs = LogEntry.query.all()

    pdf_path = generate_report(
        incidents,
        logs
    )

    return send_file(
        pdf_path,
        as_attachment=True
    )


# =====================================================
# CREATE UPLOAD FOLDER
# =====================================================

if not os.path.exists(
    app.config['UPLOAD_FOLDER']
):
    os.makedirs(
        app.config['UPLOAD_FOLDER']
    )


if not os.path.exists(
    'final_report'
):
    os.makedirs(
        'final_report'
    )


# =====================================================
# RUN APPLICATION
# =====================================================

if __name__ == '__main__':

    with app.app_context():

        db.create_all()

    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000
    )