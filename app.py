from flask import Flask, render_template
from db import db   #import the SQLAlchemy instance from db.py
from user.models import Users, Devices, Metadata, Alerts   #import models to create tables
from user.routes import user_bp   #import user blueprint for routes
from seed import seed_data   #import seed function to add sample data to the database for prototype purposes
from dotenv import load_dotenv      #load environment variables from .env file
import os           #access environment variables
import sys

load_dotenv()   
app = Flask(__name__)   #create a flask app instance
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE")       #configure the database URI  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False    #track modifications setting
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")    #set secret key for session management
app.register_blueprint(user_bp)        #register user blueprint

db.init_app(app)   #initialize SQLAlchemy instance with app
with app.app_context():
    if "--reset-db" in sys.argv:     #check command line argument to reset the database
        print("Resetting database...")
        db.drop_all()      #drop all tables if reset flag is provided
        db.create_all()
        seed_data()    #seed the database with sample data for prototype
    else:
        db.create_all()
        seed_data()
    
    print('Created database!')

#define routes for different pages
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':   
    app.run(debug=True)