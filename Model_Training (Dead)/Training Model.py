import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import PowerTransformer
import joblib
import numpy as np

# load training data
print("Loading v26 master training data...")
# master_training_data_boosted_v18.csv - ORIGINAL OG, but dogshit in realworld
# master_training_data_boosted_is_low_port_count_v24.csv
# master_training_data_boosted_is_low_port_count_dest_port_actual_v25.csv
# master_training_data_boosted_removed_calc_4features_v26.csv #removed 4features calculation in merging - from homedataset
# master_training_data_boosted_removed_calc_4features_v27.csv #boosting * 80 from 10
# master_training_data_boosted_removed_calc_4features_v28.csv # boosting * 10 from *80
# master_training_data_v29.csv
# updated_ports_boosted10.csv #no merging, only homedataset
# master_training_data_v30.csv # idk anymore updated port again



csv_filename = "master_training_data_v30.csv" # Updated name
df = pd.read_csv(csv_filename)
df.columns = df.columns.str.strip()


# fwd - me to outside - computer -> internet - outbound
# bwd - outside to me - internet -> computer - inbound
features = [
    'Source Port',      # port of the sender device
    'Destination Port', # port of the receiver
    'Protocol',         # type of language, TCP, UDP

    'Total Fwd Packets',        # number of packets from me to internet - me to internet - source to destination
    'Total Backward Packets',   # number of packets from internet to me - internet to me - destination to source

    'Total Length of Fwd Packets', # total size (in bytes) of all data sent out
    'Total Length of Bwd Packets', # total size of all data recieved

    'Fwd Packet Length Mean',   # the average size of outgoing packets
    'Packet Length Std',        # std, measures how much the size of individual packeets varies from the typical average
    'Fwd Packet Length Max',    # the size of the single largest outgoing packet
    'Packet Length Variance',   # similar to std, measures the mathematical spread of packet size, mainly meant for extreme outliers

    'Flow IAT Mean', # malware check-ins, if consistent timing such as automated intervals, they create a distinct, interval arrival time, between packets

    'SYN Flag Count', # starting conversation
    'ACK Flag Count', # acknowledging data
    'RST Flag Count', # used to force close a connection, high rst counts often mean scanning hitting a closed port
    'FIN Flag Count', # simply closes a connection, unlike force close

    'Flow Bytes/s',     # high bytes/s can indicate a data leak or heavy download
    'Flow Packets/s',   # frequency, high packets/s with small byte sizes can tell if DDoS

    'Subflow Fwd Bytes',    # measure volume within segments of total flow, this helps in detecting bursty behavior,
    'Subflow Fwd Packets',  # measure volume within segments of total flow, this helps in detecting bursty behavior

    'Packet_to_Port_Ratio', # total packets / unique ports, low = sender is scanning for ports i.e. port scanning
    'Payload_Ratio',        # fwd length / bwd length, high = my device uploading much more data than its downloading
    'SYN_Density',          # SYN flags / total packets, high = sender trying to start thousands of conversations but never actually saying  anything meaningful
    'is_low_port_count'     # true or false, finding if a destination is well known port, or poking port that is dangerous
]

# filter benign
print("Cleaning data for training...")
label_col = 'Label' #MERGING MON AND HOME
X = df[df[label_col] == 'BENIGN'][features].copy() # USED AFTER MERGING MONDAY AND HOMEDATASET
# X = df[features].copy() #USED FOR ONLY HOME DATASET

X.replace([np.inf, -np.inf], 0, inplace=True)
X.fillna(0, inplace=True)

#scaling, could test withh linear, uncomment fit_transform
print("Scaling features...")
#scaler = StandardScaler() #change from StandardScalar to PowerTransformer (method='yea-johnson')
scaler = PowerTransformer(method='yeo-johnson')
#X_scaled = scaler.fit_transform(X)
X_train_scaled = scaler.fit_transform(X)

# heavy lifting
model = IsolationForest(
    n_estimators=200,
    max_samples=1024,       #lets outliers 1024, auto
    contamination=0.15,     # tells model to expect more outliers, higher means "dirty" data
    random_state=42,
    verbose=1,
    n_jobs=-1,
    bootstrap=True
)

print(f"Training v31 on {len(X)} rows with {len(features)} features...")
model.fit(X_train_scaled) # CHANGE FROM x_scaled --> X_train_scaled


# .joblib is efficient for pi
joblib.dump(model, "anomaly_detector_v31.joblib")
joblib.dump(scaler, "scaler_v31.joblib")
joblib.dump(features, "feature_list_v31.joblib")

print(f"\n--- SUCCESS ---")
