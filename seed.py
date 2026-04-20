from db import db
from user.models import Users, Devices, Flows, Metadata, Alerts


def seed_data():         #for prototype, add some sample data to the database
    """
    Populates the database with a minimal set of fake data so the dashboard
    actually has something to show on first run. Without this, every page
    would just be empty tables which makes demoing the project painful.

    The guard at the top means this only runs once — if you restart the server
    the data won't get doubled up.
    """
    if Users.query.first(): #check if there are already users in the database, if so skip seeding to avoid duplicates
        print("Database already seeded!")
        return

    print("Seeding database with sample data...")

    # Demo user.
    # The password is intentionally simple because this is just prototype data.
    user = Users(email="test@gmail.com", name="Test", role="USER")
    user.set_password("password_000")       #set password for the user
    db.session.add(user)       #add user to database
    db.session.commit()        #save the use

    # Two fake laptops on a typical home or office LAN subnet.
    device1 = Devices(device_name="Laptop1", mac_addr="00:1A:2B:3C:4D:5E",
                      ip_addr="192.168.1.102", status="ACTIVE")
    device2 = Devices(device_name="Laptop2", mac_addr="00:1A:2B:3C:4D:5F",
                      ip_addr="192.168.1.122", status="ACTIVE")
    db.session.add_all([device1, device2])      #add devices to database
    db.session.commit()     #save devices

    # One TCP flow from Laptop1 to Laptop2 on port 80.
    # The values are made up, but they look like a short web request.
    flow = Flows(
        src_ip="192.168.1.102", dst_ip="192.168.1.122",
        src_port=5000, dst_port=80,
        protocol="TCP",
        total_packets=10, total_bytes=5000,
        fwd_packets=6, bwd_packets=4,  # Six packets forward, four replies.
        flow_bytes_per_sec=95.5,
        syn_count=2, ack_count=5,
        packet_to_port_ratio=1.5,
        payload_ratio=0.6  # Most of the bytes are payload instead of headers.
    )
    db.session.add(flow)
    db.session.commit()

    # Link the flow to the two devices so we know which machines talked.
    metadata = Metadata(
        flow_id=flow.flow_id,
        src_mac_id=device1.device_id, dst_mac_id=device2.device_id,
        src_port=5000, dst_port=80,
        src_ip="192.168.1.102", dst_ip="192.168.1.122",
        protocol="TCP"
    )
    db.session.add(metadata)
    db.session.commit()

    # Add a high-severity alert so the alerts page is not empty.
    # A score of 0.95 means the model was very confident it was suspicious.
    alert = Alerts(
        flow_id=flow.flow_id,
        severity="HIGH", status="OPEN",
        score=0.95, is_anomaly=True,
        description="Suspicious flow detected between Laptop1 and Laptop2"
    )
    db.session.add(alert)
    db.session.commit()

    print("Database seeding completed!")
