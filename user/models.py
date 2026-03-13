from db import db   #import database connection
from sqlalchemy import func   #import func for now()
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError   #for password verification failure
import os

ph = PasswordHasher()   #create an instance of PasswordHasher

class Users(db.Model):   #define User model inheriting from db.Model
    __tablename__ = 'users'   #specify table name for SQLAlchemy
    user_id = db.Column(db.Integer, primary_key = True)     
    email = db.Column(db.String(100), unique=True, nullable = False) 
    hashed_password = db.Column(db.String(300), nullable = False)
    name = db.Column(db.String(100), nullable = False)
    role = db.Column(db.String(20), nullable = False, default = "USER")     #'ADMIN' or 'USER'
    #username = db.Column(db.String(80), unique = True, nullable = False) 

    #hash and set the password
    def set_password(self, password):     
        self.hashed_password = ph.hash(password)
    
    def verify_password(self, password):  
        try:
            return ph.verify(self.hashed_password, password)   #verify the password 
            #print("Password verification successful")   #verification successful
        except VerifyMismatchError:
            #print("Invalid password")   #verification failed
            return False

    def assign_admin(self):
        if self.email == os.getenv("ADMIN_EMAIL"):
            self.role = "ADMIN"

    @staticmethod
    def find_by_email(email):     #find user by email
        if not email:
            return None
        return Users.query.filter_by(email=email).first()   #query the database for a user with the given email
        
    

class Devices(db.Model):   
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key = True)   
    device_name = db.Column(db.String(100), nullable = False)  
    #mac_addr = db.Column(db.String(50), nullable = False)  
    ip_addr = db.Column(db.String(50), nullable = False)  
    status = db.Column(db.String(20), nullable = False)     #'ACTIVE' or 'INACTIVE'
    first_seen = db.Column(db.DateTime, nullable = False, default = func.now())
    last_seen = db.Column(db.DateTime, nullable = False, default = func.now(), onupdate=func.now())

class Metadata(db.Model):   
    __tablename__ = 'packet_metadata'
    packet_id = db.Column(db.Integer, primary_key = True)  
    timestamp = db.Column(db.DateTime, nullable = False, default = func.now()) 
    src_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable = False)  
    dst_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable = False)
    src_port = db.Column(db.Integer, nullable = False)
    dst_port = db.Column(db.Integer, nullable = False)
    src_ip = db.Column(db.String(50), nullable = False)   #not foreign key, store IP directly for easier querying
    dst_ip = db.Column(db.String(50), nullable = False)
    protocol = db.Column(db.String(20), nullable = False)
    packet_size = db.Column(db.Integer, nullable = False)

    #relationships to link metadata to devices
    src_device = db.relationship('Devices', foreign_keys = [src_id], backref='sent_packets')      
    dst_device = db.relationship('Devices', foreign_keys = [dst_id], backref='received_packets')
    
class Alerts(db.Model):   
    __tablename__ = 'alerts'
    alert_id = db.Column(db.Integer, primary_key = True)  
    timestamp = db.Column(db.DateTime, nullable = False, default = func.now()) 
    packet_id = db.Column(db.Integer, db.ForeignKey('packet_metadata.packet_id'), nullable = False)  
    severity = db.Column(db.String(50), nullable = False)
    status = db.Column(db.String(20), nullable = False)     #'OPEN', 'IN_PROGRESS', or 'RESOLVED'
    score = db.Column(db.Integer, nullable = False)   #severity score
    #user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable = True)  #alert forms can be assigned to users, but not required
    description = db.Column(db.String(200), nullable = False)

    #relationship to link alert to packet metadata
    packet = db.relationship('Metadata', backref='alerts')  
    #relationship to link alert to user (if assigned)
    #assigned_user = db.relationship('Users', backref='assigned_alerts') 
