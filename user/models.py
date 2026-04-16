from db import db  # Shared database connection.
from sqlalchemy import func  # Used for server-side timestamps.
from werkzeug.security import generate_password_hash, check_password_hash
import os

class Users(db.Model):  # User account model.
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique=True, nullable = False)
    hashed_password = db.Column(db.String(300), nullable = False)
    name = db.Column(db.String(100), nullable = False)
    role = db.Column(db.String(20), nullable = False, default = "USER")  # ADMIN or USER.

    # Hash and store the password.
    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.hashed_password, password)

    def assign_admin(self):
        if self.email == os.getenv("ADMIN_EMAIL"):
            self.role = "ADMIN"

    @staticmethod
    def find_by_email(email):  # Look up a user by email.
        if not email:
            return None
        return Users.query.filter_by(email=email).first()
    

class Devices(db.Model):   
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key = True)   
    device_name = db.Column(db.String(100), nullable = False)  
    mac_addr = db.Column(db.String(50), nullable = False)  # MAC address of the device.
    ip_addr = db.Column(db.String(50), nullable = False)  
    status = db.Column(db.String(20), nullable = False)  # ACTIVE or INACTIVE.
    first_seen = db.Column(db.DateTime, nullable = False, default = func.now())
    last_seen = db.Column(db.DateTime, nullable = False, default = func.now(), onupdate=func.now())


class Flows(db.Model):
    __tablename__ = 'flows'
    flow_id = db.Column(db.Integer, primary_key = True)  
    src_ip = db.Column(db.String(50), nullable = False)   
    dst_ip = db.Column(db.String(50), nullable = False)
    src_port = db.Column(db.Integer, nullable = False)
    dst_port = db.Column(db.Integer, nullable = False)
    protocol = db.Column(db.String(20), nullable = False)       
    total_packets = db.Column(db.Integer, nullable = False)  # Total packets in the flow.
    total_bytes = db.Column(db.Integer, nullable = False)
    start_time = db.Column(db.DateTime, nullable = False, default = func.now())
    end_time = db.Column(db.DateTime, nullable = False, default = func.now())
    fwd_packets = db.Column(db.Integer, nullable = False)  # Packets in the forward direction.
    bwd_packets = db.Column(db.Integer, nullable = False)   
    flow_bytes_per_sec = db.Column(db.Float, nullable = False)  # Flow bytes per second.
    syn_count = db.Column(db.Integer, nullable = False)  # Number of SYN packets in the flow.
    ack_count = db.Column(db.Integer, nullable = False)  # Number of ACK packets.
    packet_to_port_ratio = db.Column(db.Float, nullable = False)  # Packets per destination port.
    payload_ratio = db.Column(db.Float, nullable = False)  # Payload bytes as a share of total bytes.



class Metadata(db.Model):   
    __tablename__ = 'packet_metadata'
    packet_id = db.Column(db.Integer, primary_key = True)  
    timestamp = db.Column(db.DateTime, nullable = False, default = func.now()) 
    flow_id = db.Column(db.Integer, db.ForeignKey('flows.flow_id'), nullable = False)  
    src_mac_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable = False)  
    dst_mac_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable = False)
    src_port = db.Column(db.Integer, nullable = False)
    dst_port = db.Column(db.Integer, nullable = False)
    src_ip = db.Column(db.String(50), nullable = False)  # Store the IP directly for easier querying.
    dst_ip = db.Column(db.String(50), nullable = False)
    protocol = db.Column(db.String(20), nullable = False)
    # Length is not stored separately right now.

    # Link metadata back to the source and destination devices.
    src_device = db.relationship('Devices', foreign_keys = [src_mac_id], backref='sent_packets')
    dst_device = db.relationship('Devices', foreign_keys = [dst_mac_id], backref='received_packets')
    
    # Link each packet record to its flow.
    flow_metadata = db.relationship('Flows', foreign_keys = [flow_id], backref='packets')


class Alerts(db.Model):
    __tablename__ = 'alerts'
    alert_id = db.Column(db.Integer, primary_key = True)
    timestamp = db.Column(db.DateTime, nullable = False, default = func.now())
    flow_id = db.Column(db.Integer, db.ForeignKey('flows.flow_id'), nullable = True)  # Optional for window-level detections.
    severity = db.Column(db.String(50), nullable = False)
    status = db.Column(db.String(20), nullable = False)  # OPEN, IN_PROGRESS, or RESOLVED.
    score = db.Column(db.Float, nullable = False)  # Severity or anomaly score.
    is_anomaly = db.Column(db.Boolean, nullable = False, default=False)  # True when the alert is anomalous.
    description = db.Column(db.String(200), nullable = False)

    # Window-level detection fields.
    detection_type = db.Column(db.String(20), nullable = True)  # RULE, AI, or HYBRID.
    alert_name = db.Column(db.String(100), nullable = True)  # Rule-based alert name.
    window_start = db.Column(db.DateTime, nullable = True)  # Start of the detection window.
    anomaly_score = db.Column(db.Float, nullable = True)  # AI anomaly score.
    packet_count = db.Column(db.Integer, nullable = True)  # Packets captured in the window.


    # Link alerts back to flows.
    flow_alert = db.relationship('Flows', foreign_keys = [flow_id], backref='alerts')
    # A user relationship can be added later if alerts need ownership.
