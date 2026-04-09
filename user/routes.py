from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from user.models import Users, Devices, Metadata, Alerts
from db import db

user_bp = Blueprint('user_bp', __name__)   #create a blueprint for user routes

#user/auth routes
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
    
    #fetch user info from session
    user_info = {'user_id': session.get('user_id'), 'name': session.get('name'),
                'email': session.get('email'),'role': session.get('role')
    }
    print(f"Load profile for user: {user_info['email']}, role: {user_info['role']}")
    return render_template('profile.html', user = user_info)


@user_bp.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):        #check if user is logged in
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    return render_template('dashboard.html')


@user_bp.route('/alerts')
def alerts():
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    #fetch alerts from database, order by most recent first
    alerts = Alerts.query.order_by(Alerts.timestamp.desc()).all()
    #return render_template('alerts.html', alerts=alerts)
    return render_template('alert_page.html', alerts = alerts)


@user_bp.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    if not session.get('logged_in'):
        flash("Must log in to access this page", "error")
        return redirect(url_for('user_bp.login'))
    
    alert = Alerts.query.get(alert_id)     #fetch alert by ID
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))
    
    #metadata = Metadata.query.get(alert.packet_id)     #fetch associated metadata
    
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
    
    alert = Alerts.query.get(alert_id)     #fetch alert by ID
    if not alert:
        flash("Alert not found", "error")
        return redirect(url_for('user_bp.alerts'))
    
    if alert.status == "RESOLVED":
        flash("Alert is already resolved", "info")
        return redirect(url_for('user_bp.alert_detail', alert_id = alert_id))
    
    alert.status = "RESOLVED"     #update alert status to resolved
    db.session.commit()        #save changes to database
    flash("Alert marked as resolved", "success")
    return redirect(url_for('user_bp.alert_detail', alert_id = alert_id))