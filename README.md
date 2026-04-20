![CI](https://github.com/SJSU-CMPE-195/group-project-team-13/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-89%25-brightgreen)

# LANGuard IDS on a Raspberry Pi

With the growing popularity of cybercrime, many homes and businesses are affected by online threats that target devices that are left vulnerable to attacks. Without dedicated security working to protect these devices, they are left open to attacks. Technology to detect malicious attacks exists, but is expensive and complex. LANGuard is not only a Wi-Fi analyer to detect network traffic in real-time, but also acts as a remedy to the existence inequality issue in which lower-income class and small companies unable to afford to a secured network and at risk of being cyber-attack targets

## Team 13

 - Isaiah Villanueva (Villanuevai1)
 - Fernando Ruiz (fernandoruiz02)
 - Hoang Nhat Ho (supernova0216)
 - Anthony Truong (tonyspaghetti)

 **Advisor:** Professor Bhawandeep Singh Harsh

 ---

## Demo

[Link to demo video or GIF]
https://drive.google.com/file/d/1vpZKb1r3NBTUbrT9UaBzOmEkiChGC-hf/view?usp=drive_link


- Prototype login credentials with seeding data 

```
Email: test@gmail.com
Password: password_000
```
<img width="755" height="771" alt="Image" src="https://github.com/user-attachments/assets/9e3fb8dc-1765-4b66-bce7-8d01380d2e2d" />
<img width="749" height="686" alt="Image" src="https://github.com/user-attachments/assets/b32e933e-a360-4977-9d3b-6944068c6419" />
<img width="754" height="370" alt="Image" src="https://github.com/user-attachments/assets/b95166d3-874b-41ee-8c8f-5936996a808f" />
<img width="575" height="204" alt="Image" src="https://github.com/user-attachments/assets/c10cd33d-3f5f-4640-89d8-8d0537cc01b4" />
<img width="797" height="183" alt="Image" src="https://github.com/user-attachments/assets/0d843fa4-2189-4739-9484-682745edfa52" />
<img width="793" height="171" alt="Image" src="https://github.com/user-attachments/assets/e58f7b7c-67aa-455c-bd7d-2def6aac6971" />
<img width="664" height="186" alt="Image" src="https://github.com/user-attachments/assets/e32c1c46-73e3-4388-82e8-418c20b35471" />
<img width="786" height="171" alt="Image" src="https://github.com/user-attachments/assets/c92fb544-8a02-49fe-9490-1a31d92ceea0" />


---
## Getting Started

### Prerequisites
(List of all software, tools, accounts needed before setup)
 - Pi 4/5
 - Customizable Network switch (For Testing)
 - SQLite
 - Npcap
 - Scapy
 - pandas (Reads csv files)
 - sklearn (Model training)
 - Python 3.1+
 - pip
 - Git


### Installation
(Step by step instructions to set the project locally)

run the scripts locally. 

```bash

# Clone the repository
git clone https://github.com/SJSU-CMPE-195/group-project-team-13.git
cd group-project-team-13


# Set up environment variables
python3 -m venv .venv
source venv/bin/activate  # Linux/macOS
.venv\Scripts\activate  # Windows


# Install dependencies
pip install -r requirements.txt

```

### Configuration
(How to configure environment variables, API keys, etc)

Create a .env file in the root directory of the project and add the following:
       
        
        FLASK_ENV=development       #set the environment to development  
        DATABASE=your_database_url      #database url for sqlite
        SECRET_KEY=your_secret_key      #for session management
        

### Running the Application
(Commands to start the application)
 - run website script
 - run packets capture --> feature --> analysis --> scoring (is going to be all in one)

 - run the web application:

    ```bash
    flask run
    #OR
    python3 app.py
    #OR
    python app.py
    ```

---

## Usage
(Basic instructions on how to use the application)
- There isn't ultimately much to be using, rather its mainly viewing. It is meant to display the anomaly score, and supposed to tell you what kind of anomaly. 

- Web application:
Click the link in the Terminal, it will navigate to ```http://127.0.0.1:5000``` on a web browser.

---

## Project Structure
(Brief overview of folder/file organization)

```
group-project-team-13
├── [folder]/           # Description
├── docs/               # Documentation files
├── static/             # For frontend styling
├── templates/          # Frontend views
├── tests/              # Test files
├── user/               # User models
├── app.py              # Main Flask app
└── README.md           # Overiew and instructions
```

---

## Acknowledgments

- Role-based accessed method and HTML/CSS layout adapted from repo ```https://github.com/trulymittal/role-based-access-control```. The original structure was used as a base, mostly for frontend, and has been developed and customized to fit project requirements and improve UI/UX

- Argon2 library for secure password hashing
