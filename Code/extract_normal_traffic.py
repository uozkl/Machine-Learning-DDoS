import pandas as pd
import os

path = './Dataset'
normal_traffic = []
files = []
for r, d, f in os.walk(path):
    for file in f:
        if '.csv' in file:
            files.append(os.path.join(r, file))
for f in files:
    print(f)
    #df = pd.read_csv("D:\\4900 Project\\Dataset\\DNS\\DrDoS_DNS_split\\DrDoS_DNS_1.csv", low_memory=False)
    df = pd.read_csv(f, low_memory=False)
    index_of_label = list(df.columns).index("Label")
    for packet in df.values:
        if packet[index_of_label] == "BENIGN":
            normal_traffic.append(packet)

normal_df=pd.DataFrame(normal_traffic,columns=pd.columns)