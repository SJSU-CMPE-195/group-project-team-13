from flask import Flask, render_template
from db import db
from user.models import Users, Devices, Metadata, Alerts
from user.routes import user_bp
from seed import seed_data
from dotenv import load_dotenv
import os
import subprocess
import threading

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

db.init_app(app)
app.register_blueprint(user_bp)

# Start background detection scheduler AFTER db.init_app
if not os.environ.get('WERKZEUG_RUN_MAIN'):
    from scheduler import start_scheduler
    scheduler = start_scheduler(app)

# Start packet capture in background
def start_packet_capture():
    """Start continuous packet capture in background"""
    try:
        print("[LANGuard] Starting background packet capture...")
        while True:
            try:
                subprocess.run(
                    ['sudo', 'timeout', '120', 'python3', 'capture_to_csv.py'],
                    timeout=130,
                    capture_output=True
                )
            except Exception as e:
                print(f"[LANGuard] Capture error: {e}")

            import time
            time.sleep(5)
    except KeyboardInterrupt:
        print("[LANGuard] Packet capture stopped")

# Start capture in background thread (non-blocking)
capture_thread = threading.Thread(target=start_packet_capture, daemon=True)

with app.app_context():
    db.create_all()
    seed_data()
    db.session.query(Alerts).delete()  # Clear fake alerts
    db.session.commit()
    print('Created database!')
    capture_thread.start()

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
