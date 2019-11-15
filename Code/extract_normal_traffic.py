import pandas as pd
import os
import time
import copy

#path = './Dataset'
path = 'D:/4900 Project/Dataset'

files = []
cols = [
    'Unnamed: 0', 'Flow ID', ' Source IP', ' Source Port', ' Destination IP', ' Destination Port', ' Protocol',
    ' Timestamp', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', 'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min', ' Fwd Packet Length Mean',
    ' Fwd Packet Length Std', 'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
    ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total',
    ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
    ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std',
    ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min', 'SimillarHTTP', ' Inbound',
    ' Label'
]
for r, d, f in os.walk(path):
    for file in f:
        if '.csv' in file and "NUSW-NB15_features" not in file:
            files.append(os.path.join(r, file))
def extract_normal(files):
    normal_traffic = []
    counter = 0
    for f in files:
        print(f)
        #df = pd.read_csv("D:\\4900 Project\\Dataset\\DNS\\DrDoS_DNS_split\\DrDoS_DNS_1.csv", low_memory=False)
        try:
            df = pd.read_csv(f, low_memory=False)
            for packet in df.values:
                if packet[len(list(df.columns))-1] == "BENIGN":
                    normal_traffic.append(packet)
        except Exception as e:
            print("ERROR in", f, "\n", e)
        counter += 1
        if counter % 80 == 0:
            normal_df = pd.DataFrame(normal_traffic, columns=cols)
            while True:
                try:
                    normal_df.to_csv("D:/BENIGN_" + str(counter // 80) + ".csv", mode='w', index=False)
                    break
                except Exception as e:
                    print(e)
                    time.sleep(5)
            normal_traffic = []
            normal_df = None

def extract_malicious(files):
    malicious_traffic = []
    counter = 0
    for f in files:
        print(f)
        if counter >= 60000:
            break
        #df = pd.read_csv("D:\\4900 Project\\Dataset\\DNS\\DrDoS_DNS_split\\DrDoS_DNS_1.csv", low_memory=False)
        try:
            df = pd.read_csv(f, low_memory=False)
            index = len(list(df.columns)) - 1
            for packet in df.values:
                if packet[index] != "BENIGN":
                    tmp = copy.deepcopy(packet)
                    tmp[index]="MALICIOUS"
                    malicious_traffic.append(tmp)
                    counter += 1
                if counter >= 60000:
                    break
        except Exception as e:
            print("ERROR in", f, "\n", e)
