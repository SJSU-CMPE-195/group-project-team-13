from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from user.models import Users, Devices, Metadata, Alerts
from db import db
import subprocess
import os
from pathlib import Path

user_bp = Blueprint('user_bp', __name__)  # Blueprint for user routes.

# User and auth routes.
@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = Users.find_by_email(email)
        if not user:
            flash("Invalid email or password", "error")
            return redirect(url_for('user_bp.login'))
        
        if not user.verify_password(password):
            flash("Invalid password", "error")
            return redirect(url_for('user_bp.login'))
        
        # Keep the session in sync with the signed-in user.
        session['logged_in'] = True
        session['user_id'] = user.user_id
        session['name'] = user.name
        session['email'] = user.email
        session['role'] = user.role
        
        print(f"Login successful: {email}, role: {user.role}")
        return redirect(url_for('user_bp.dashboard'))
    return render_template('login.html')


@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']       
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if len(password) < 5:
            flash("Password must be at least 5 characters long", "error")
            return redirect(url_for('user_bp.register'))
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('user_bp.register'))
        
        if Users.find_by_email(email):
            flash("Email already registered", "error")
            return redirect(url_for('user_bp.register'))
        
        # All checks passed, so create the user.
        new_user = Users(email=email, name=name)
        new_user.set_password(password)
        new_user.assign_admin()
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Log in now", "success")
        return redirect(url_for('user_bp.login'))
    return render_template('register.html')


@user_bp.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully. See you soon.", "success")
    return redirect(url_for('user_bp.login'))


@user_bp.route('/profile')
def profile():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    # Pull the current user's details from the session.
    user_info = {'user_id': session.get('user_id'), 'name': session.get('name'),
                'email': session.get('email'),'role': session.get('role')
    }
    print(f"Load profile for user: {user_info['email']}, role: {user_info['role']}")
    return render_template('profile.html', user = user_info)


@user_bp.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))

    recent_alerts = Alerts.query.order_by(Alerts.timestamp.desc()).limit(10).all()
    threats_blocked = Alerts.query.filter_by(status='RESOLVED').count()
    alert_count = Alerts.query.filter_by(status='OPEN').count()
    packet_count = Metadata.query.count()
    total_alerts = Alerts.query.count()
    high_alerts = Alerts.query.filter_by(severity='High').count()

    return render_template('dashboard.html', alerts=recent_alerts, packet_count=packet_count,
                           alert_count=alert_count, threats_blocked=threats_blocked,
                           total_alerts=total_alerts, high_alerts=high_alerts)


@user_bp.route('/alerts')
def alerts():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    # Pull alerts from the database, newest first.
    alerts = Alerts.query.order_by(Alerts.timestamp.desc()).all()
    return render_template('alert_page.html', alerts = alerts)


@user_bp.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    alert = Alerts.query.get(alert_id)
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))
    
    return render_template('alert_detail.html', alert = alert,)


@user_bp.route('/add_alert', methods=['POST'])
def add_alert():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    packet_id = request.form['packet_id']




@user_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))

    alert = Alerts.query.get(alert_id)
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))

    if alert.status == "RESOLVED":
        flash("Alert is already resolved", "info")
        return redirect(url_for('user_bp.alert_detail', alert_id = alert_id))

    alert.status = "RESOLVED"
    db.session.commit()
    flash("Alert marked as resolved", "success")
    return redirect(url_for('user_bp.alert_detail', alert_id = alert_id))


@user_bp.route('/run_detection', methods=['POST'])
def run_detection():
    """Trigger the detection pipeline (extract features → run detectors → store alerts)"""
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    if session.get('role') != 'ADMIN':
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403

    try:
        # Step 1: extract features from the captured packets.
        print("[Flask] Extracting features...")
        result = subprocess.run(
            ['python', 'Model_Pipeline/extract_features.py'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': f'Feature extraction failed: {result.stderr}'}), 500

        # Step 2: run the detectors and store the results.
        print("[Flask] Running detection pipeline...")
        from detector_runner import run_detection_pipeline
        from app import app

        success = run_detection_pipeline(db, app.app_context())
        if not success:
            return jsonify({'status': 'error', 'message': 'Detection pipeline failed'}), 500

        flash("Detection pipeline completed successfully!", "success")
        return redirect(url_for('user_bp.alerts'))

    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Detection pipeline timeout'}), 500
    except Exception as e:
        print(f"[Flask] Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
