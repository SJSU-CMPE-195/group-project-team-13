from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from user.models import Users, Devices, Metadata, Alerts
from db import db
from datetime import datetime
import subprocess
import os
from pathlib import Path

user_bp = Blueprint('user_bp', __name__)  # Blueprint for user routes.

# User and auth routes.
@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']       #get from the form
        password = request.form['password']

        user = Users.find_by_email(email)        #find user
        if not user:
            flash("Invalid email or password", "error")
            return redirect(url_for('user_bp.login'))
        
        if not user.verify_password(password):       
            flash("Invalid password", "error")          #password does not match
            return redirect(url_for('user_bp.login'))       #stay on login page  
        
        #set session variables when login is successful
        session['logged_in'] = True  #mark user as logged in
        session['user_id'] = user.user_id    #store user ID in session
        session['name'] = user.name
        session['email'] = user.email
        session['role'] = user.role
        
        print(f"Login successful: {email}, role: {user.role}")   #see console output
        #if user['role'] == 'ADMIN':
        #    return redirect(url_for('user_bp.manage_users'))    #redirect to admin manage users page
        return redirect(url_for('user_bp.dashboard'))     #after successful login
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
        
        if Users.find_by_email(email):      #check if email already exists
            flash("Email already registered", "error")
            return redirect(url_for('user_bp.register'))    
        
        #all checks passed, create new user
        new_user = Users(email=email, name=name)
        new_user.set_password(password)     #hash and set the password
        new_user.assign_admin()     #check if email matches admin email
        if new_user.role == "ADMIN":
            new_user.allowed_resolve_alerts = True

        db.session.add(new_user)       #add user to database
        db.session.commit()        #commit changes to database
        flash("Registration successful! Log in now", "success")
        return redirect(url_for('user_bp.login'))       #redirect to login page after successful registration
    return render_template('register.html')    


@user_bp.route('/logout')
def logout():
    session.clear()     #clear all session data to log out
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
    return render_template('profile.html', user=user_info)


@user_bp.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))

    recent_alerts = Alerts.query.order_by(Alerts.timestamp.desc()).limit(10).all()
    threats_blocked = Alerts.query.filter_by(status='RESOLVED').count()      #count number of resolved alerts
    alert_count = Alerts.query.filter_by(status='OPEN').count()     #total number of alerts
    packet_count = Metadata.query.count()        #total number of packets from database
    total_alerts = Alerts.query.count()      #total number of alerts
    high_alerts = Alerts.query.filter(Alerts.severity.ilike('High')).count()       #count high severity alerts
    resolve_alerts = Alerts.query.filter_by(status='RESOLVED').order_by(Alerts.timestamp.desc()).limit(5).all()     #recent resolved alerts 

    return render_template('dashboard.html', alerts=recent_alerts, packet_count=packet_count,
                           alert_count=alert_count, threats_blocked=threats_blocked,
                           total_alerts=total_alerts, high_alerts=high_alerts, resolve_alerts=resolve_alerts)


@user_bp.route('/alerts')
def alerts():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    # Pull alerts from the database, newest first.
    alerts = Alerts.query.order_by(Alerts.timestamp.desc()).all()
    return render_template('alert_page.html', alerts=alerts)


@user_bp.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    alert = Alerts.query.get(alert_id)        #fetch alert by ID
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))
    
    return render_template('alert_detail.html', alert=alert)

'''
@user_bp.route('/add_alert', methods=['POST'])
def add_alert():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    packet_id = request.form['packet_id']
'''


@user_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    user = Users.query.get(session.get('user_id'))     #fetch current user 
    if session.get('role') != 'ADMIN' and not user.allowed_resolve_alerts:     #only admin can resolve alerts
        flash("Admin access required to resolve alerts", "error")
        return redirect(url_for('user_bp.alert_detail', alert_id=alert_id))

    alert = Alerts.query.get(alert_id)       #fetch alert by ID
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))

    if alert.status == "RESOLVED":
        flash("Alert is already resolved", "info")
        return redirect(url_for('user_bp.alert_detail', alert_id=alert_id))

    alert.status = "RESOLVED"     #update alert status to resolved
    alert.resolved_by = session.get('user_id')     #set the user who resolved the alert
    alert.resolved_at = datetime.utcnow()   
    db.session.commit()        #save changes to database
    flash("Alert marked as resolved", "success")
    return redirect(url_for('user_bp.alert_detail', alert_id=alert_id))


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


@user_bp.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    user = Users.query.get(session.get('user_id'))     #fetch current user from database
    if request.method == 'POST':
        new_name = request.form['name']     #get updated name
        if not new_name:            #validate new name
            flash("Name cannot be empty", "error")
            return redirect(url_for('user_bp.edit_profile'))
        
        if new_name == user.name:     #check if new name is different from current name
            flash("New name must be different from current name", "error")
            return redirect(url_for('user_bp.edit_profile'))
        
        user.name = new_name        #update user name
        db.session.commit()        

        session['name'] = new_name     #update name in session
        flash("Profile updated successfully", "success")
        return redirect(url_for('user_bp.profile'))
    
    return render_template('edit_profile.html', user=user)


@user_bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    user = Users.query.get(session.get('user_id'))     #fetch current user from database
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not user.verify_password(current_password):       #verify current password
            flash("Current password is incorrect", "error")
            return redirect(url_for('user_bp.change_password'))
        
        if new_password == current_password:     #check if new password is different from current password
            flash("New password must be different from current password", "error")
            return redirect(url_for('user_bp.change_password'))
        
        if len(new_password) < 5:   #validate new password length
            flash("Password must be at least 5 characters long", "error")
            return redirect(url_for('user_bp.change_password'))
        
        if new_password != confirm_password:
            flash("Password does not match", "error")
            return redirect(url_for('user_bp.change_password'))
        
        user.set_password(new_password)     #hash and set new password
        db.session.commit()        

        flash("Password changed successfully", "success")
        return redirect(url_for('user_bp.profile'))
    
    return render_template('change_password.html')


@user_bp.route('/admin/manage_users')
def manage_users():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    if session.get('role') != 'ADMIN':
        flash("Unauthorized access: ADMIN only", "error")
        return redirect(url_for('user_bp.dashboard'))
    
    users = Users.query.filter(Users.role != 'ADMIN').all()     #fetch all users from database
    return render_template('manage_users.html', users=users)


@user_bp.route('/admin/grant_permission/<int:user_id>', methods=['POST'])
def grant_permission(user_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    if session.get('role') != 'ADMIN':
        flash("Unauthorized access: ADMIN only", "error")
        return redirect(url_for('user_bp.dashboard'))
    
    user = Users.query.get(user_id)     #fetch user by ID
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_bp.manage_users'))
    
    user.allowed_resolve_alerts = not user.allowed_resolve_alerts     #toggle permission
    db.session.commit()        

    flash(f"Updates permission to {user.email}", "success")
    return redirect(url_for('user_bp.manage_users'))