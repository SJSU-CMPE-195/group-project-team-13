- application structure in app.py and db.py
    + created Flask app first and then import SQLAlchemy to configure and connect to a database ensureing the application has database connection at the beginning avoid hardship when connecting to it later. 
    + set up secret key for session management. 
    + an env file was created to store key for session, database URI, avoid hardcode into the file

- Database schema in models.py based on the script used for obtain data from detection process. The script demonstrate that it first collects packets from network, then transmit them into flow, each flow is each AI detection window. Alert found in anomaly detection process will be stored in database SQLite. New tuples will be added to the Alert table. Important data from the database will be displayed on the user interface.
    + User table: stored user credentials such as user id, email, password, name, or role in the system. Additionally, implementing hashing algorithm Argon2 for password, enhancing system confidentiality and integrity.
    + Device table: stored device's name, MAC address, IP address, or status showing if the device is active
    + Flow table: stored most variables getting from the detection process such as source IP, destination IP, protocol, and some packet information, which is how many of them are captured in the flow, total number of SYN or ACK packets, etc
    + Packet metadata table: stored packet id, source and destination MAC id, source and destination ports, etc. Also, has relationships with Devices, and Flow table with some foreign keys improving data integrity and enhancing in querying data from database
    + Alerts table: stored all information obtain from an alert found in detection process. It shows the timestamp found the alert, which flow id it comes from, evalution variables such as severiry, or score to determine if it is anomaly. Also, provides some description for user. This table also links to Flow table for the foreign key flow id.

- User routes in routes.py
    + Authentication routes such as register, log in, and log out allow user to use the services
        ++ registration form requires email, password, and name. New account will be assigned role ‘User’ automatically except account registered with admin email
        ++ after submit the form, they will be redirect to login page with pop-up message shown the registration is done and they can log into the account immediately
        ++ database will check user credentials from login page to see if it matches, if yes, redirect to dashboard page
    + Dashboard page will pull data from the database to compute and display number of threat blocked, total alerts, total packets, or specifically number of high sererity score alert.
    + Alert Table page pull all alerts store in database and displaying its detection timestamp, its severity, its status, and then place them all into a table for better observing. 
    + Alert Detail page is for viewing all information related to the alert beside variables showing in the table, such as the source and destination IP, port, protocol, the time ranges.

- UI (HTML/CSS)
    + Role-based accessed method and HTML/CSS layout adapted from repo ```https://github.com/trulymittal/role-based-access-control```. The original structure was used as a base, mostly for frontend, and has been developed and customized to fit project requirements and improve UI/UX

- Layered architecture for the website
    + presentation layer: LANGuard app
    + application layer: user routes with application services such as view alert table, see details, or mark resolves alert
    + database layer: database schema interacting with application layer to transmit data

- Stress test in locustfile.py
    + is implemented to observe how LANGuard’s system behavior under different levels of stress. 
    + use Locust since backend routes written in Python, and connect Flask app. 
    + three frequent used routes: /login, /dashboard, and /alert to evaluate how the system handles stress. 
    + load is started low with 20 concurrent users and increased until reaching 100 for the last test, 10 seconds to reach full load applied to all these three tests
