from locust import HttpUser, task, between      #import necessary modules from locust

class LANGuardUser(HttpUser):   
    wait_time = between(1, 3)       #simulate user wait time between 1 and 3 seconds after each task is executed

    @task(1)        #define a task to load the login page with a weight of 1 (less frequent than other tasks) 
    def load_login(self):
        self.client.get("/login")

    @task(2)
    def load_alerts(self):
        self.client.get("/alerts")
    
    @task(3)        #load the dashboard page with a weight of 3 (frequent used page) 
    def load_dashboard(self):
        self.client.get("/dashboard")