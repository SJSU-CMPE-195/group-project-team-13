from db import db
from user.models import Users, Devices, Flows, Metadata, Alerts

def seed_data():    #for prototype, add some sample data to the database
    if Users.query.first():     #check if there are already users in the database, if so skip seeding to avoid duplicates
        print("Database already seeded!")
        return
    
    print("Seeding database with sample data...")

    #create sample User
    user = Users(email = "test@gmail.com", name = "Test", role = "USER")
    user.set_password("password_000")     #set password for the user
    db.session.add(user)       #add user to database
    db.session.commit()        #save the user


    #create sample Device
    device1 = Devices(device_name = "Laptop1", mac_addr= "00:1A:2B:3C:4D:5E",
                      ip_addr = "192.168.1.102", status = "ACTIVE")
    device2 = Devices(device_name = "Laptop2", mac_addr= "00:1A:2B:3C:4D:5F",
                      ip_addr = "192.168.1.122", status = "ACTIVE")
    db.session.add_all([device1, device2])     #add devices to database
    db.session.commit()        #save devices


    #create sample Flow
    flow = Flows(src_ip = "192.168.1.102", dst_ip = "192.168.1.122", src_port = 5000, dst_port = 80,
                 protocol = "TCP", total_packets = 10, total_bytes = 5000, 
                 fwd_packets = 6, bwd_packets = 4, flow_bytes_per_sec = 95.5,  
                 syn_count = 2, ack_count = 5, packet_to_port_ratio = 1.5, payload_ratio = 0.6)
    db.session.add(flow)       #add flow to database
    db.session.commit()        


    #create sample Metadata
    metadata = Metadata(flow_id = flow.flow_id, src_mac_id = device1.device_id, 
                        dst_mac_id = device2.device_id, src_port = 5000, dst_port = 80, 
                        src_ip = "192.168.1.102", dst_ip = "192.168.1.122", protocol = "TCP")
    db.session.add(metadata)   #add metadata to database
    db.session.commit()        


    #create sample Alert
    alert = Alerts(flow_id = flow.flow_id, severity="HIGH", status = "OPEN", score = 0.95,
                   is_anomaly = True, description="Suspicious flow detected between Laptop1 and Laptop2")
    db.session.add(alert)     
    db.session.commit()        

    print("Database seeding completed!")