from Preprocess import Preprocess
from multiprocessing import Process, Pool
import gc
import os
import pandas as pd
import time

benign = Preprocess("D:/BENIGN.csv")
# 'SYN\\Syn_2_split\\Syn_2_3.csv'
malicious = Preprocess("D:/MALICIOUS.csv")

def cal_malicious(type, start, end):
    if type == 'conn':
        malicious.gen_feature_df_conn(start=start, end=end).to_csv("D:/Malicious_features_conn_" + str(start) + ".csv", mode='w', index=False)
        gc.collect()
    if type == 'time':
        malicious.gen_feature_df_time(start=start, end=end).to_csv("D:/Malicious_features_time_" + str(start) + ".csv", mode='w', index=False)
        gc.collect()

def cal_benign(type, start, end):
    if type == 'conn':
        benign.gen_feature_df_conn(start=start, end=end).to_csv("D:/Benign_features_conn_" + str(start) + ".csv", mode='w', index=False)
        gc.collect()

    if type == 'time':
        benign.gen_feature_df_time(start=start, end=end).to_csv("D:/Benign_features_time_" + str(start) + ".csv", mode='w', index=False)
        gc.collect()
    

if __name__ == '__main__':
    process_list = []
    pool = Pool(8)
    len_malicious = len(malicious.df)
    sep_malicious = len_malicious//20
    len_benign = len(benign.df)
    sep_benign = len_benign//20
    for i in range(20):
        m_start = sep_malicious * i +1
        m_end = (sep_malicious * (i + 1)) if i != 19 else len_malicious
        b_start = sep_benign * i +1
        b_end = (sep_benign * (i + 1)) if i!=19 else len_benign
        pool.apply_async(cal_benign, ['conn', b_start,b_end])
        pool.apply_async(cal_benign, ['time', b_start, b_end])
        pool.apply_async(cal_malicious, ['conn', m_start, m_end])
        pool.apply_async(cal_malicious, ['time', m_start, m_end])
    pool.close()
    pool.join()
    time.sleep(1)
    files = [i for i in os.listdir("D:/") if "features" in i]
    pd.concat([pd.read_csv("D:/" + i) for i in os.listdir("D:/") if ("Malicious" in i and "time" in i)]).to_csv("D:/Malicious_features_time.csv", mode='w', index=False)
    pd.concat([pd.read_csv("D:/" + i) for i in os.listdir("D:/") if ("Malicious" in i and "conn" in i)]).to_csv("D:/Malicious_features_conn.csv", mode='w', index=False)
    pd.concat([pd.read_csv("D:/" + i) for i in os.listdir("D:/") if ("Benign" in i and "time" in i)]).to_csv("D:/Benign_features_time.csv", mode='w', index=False)
    pd.concat([pd.read_csv("D:/" + i) for i in os.listdir("D:/") if ("Benign" in i and "conn" in i)]).to_csv("D:/Benign_features_conn.csv", mode='w', index=False)
