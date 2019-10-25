import pandas as pd
import sys
import re
from collections.abc import Iterable
from datetime import datetime
from numpy import mean, std

conn_based_window_size = 20
time_based_window_size = 1

# Column data type
csv_col_datatype = {
    "Protocol": "int8",
    " Protocol": "int8",
    "Dst Port": "uint16",
    " Destination Port": "uint16",
    " Source Port": "uint16",
    "Src Port": "uint16"
}
# CIC meter use a different naming method in the later version
csv_col_names_ver_1 = [
    'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Header Len', 'Bwd Header Len', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
    'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Label'
]
csv_col_names_ver_2 = [
    ' Source IP', ' Source Port', ' Destination IP', ' Destination Port', ' Protocol', ' Timestamp',
    ' Total Fwd Packets', ' Total Backward Packets', 'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Header Length', ' Bwd Header Length', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
    'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
    ' CWE Flag Count', ' ECE Flag Count', ' Label'
]

# Test file path
path = "D:/Machine-Learning-DDoS/Dataset/DNS/DrDoS_DNS_split/DrDoS_DNS_1.csv"

# Read file
encoding_type = "utf-8"
cols_inuse = csv_col_names_ver_1
while (True):
    try:
        df = pd.read_csv(path, low_memory=False, encoding=encoding_type, dtype=csv_col_datatype, usecols=cols_inuse)
        break
    except FileNotFoundError:
        path = input("CSV path error, input the path of the netflow csv file")
    except UnicodeDecodeError as e:
        if encoding_type == "utf-8":
            encoding_type = "ISO-8859-1"
        else:
            raise e
    except ValueError as e:
        if cols_inuse == csv_col_names_ver_1:
            cols_inuse = csv_col_names_ver_2
        else:
            raise e

cols_inuse = list(df.columns)

# Host ip in UNB dataset
hosts = [
    "205.174.165.81", "192.168.50.1", "192.168.50.4", "192.168.50.8", "192.168.50.5", "192.168.50.6", "192.168.50.7",
    "192.168.50.9", "192.168.50.6", "192.168.50.7", "192.168.50.8"
]


def get_conn_based_window(init_index, num_of_conn=conn_based_window_size):
    start_index = init_index - num_of_conn if init_index >= num_of_conn else 0
    return df[start_index:init_index]


def get_time_based_window(init_index, interval_in_sec=time_based_window_size):
    start_index = init_index
    timestamp_col_name = cols_inuse[__get_feature_index('time')]
    end_time = __str_to_timestamp(df[timestamp_col_name][init_index])
    while (start_index >= 0):
        start_time = __str_to_timestamp(df[timestamp_col_name][start_index])
        if end_time - start_time > interval_in_sec:
            break
        start_index -= 1
    return df[start_index + 1:init_index]


def cal_lables(df_in):
    fwd_flows = []
    bwd_flows = []
    for flow in df_in.values:
        if flow[__get_feature_index('Source IP')] in hosts:
            fwd_flows.append(flow)
        else:
            bwd_flows.append(flow)
    # Total flows in the forward direction in the window
    total_fwd = len(fwd_flows)

    # Total flows in the backward direction in the window
    total_bwd = len(bwd_flows)

    #!!
    fwd_flows_size = [i[__get_feature_index('total len fwd')] for i in fwd_flows] + [i[__get_feature_index('total len bwd')] for i in bwd_flows]
    bwd_flows_size = [i[__get_feature_index('total len bwd')] for i in fwd_flows] + [i[__get_feature_index('total len fwd')] for i in bwd_flows]
    # Total size of netflows in forward direction in the window
    total_len_fwd = sum(fwd_flows_size)

    # Total size of netflows in backward direction in the window
    total_len_bwd = sum(bwd_flows_size)

    # Minimum size of flow in forward direction in the window
    min_len_fwd = min(fwd_flows_size)

    # Minimum size of flow in backward direction in the window
    min_len_bwd = min(bwd_flows_size)

    # Maximum size of flow in forward direction in the window
    max_len_fwd = max(fwd_flows_size)

    # Maximum size of flow in backward direction in the window
    max_len_bwd = max(bwd_flows_size)

    # Mean size of flow in forward direction in the window
    mean_len_fwd = mean(fwd_flows_size)

    # Mean size of flow in backward direction in the window
    mean_len_bwd = mean(bwd_flows_size)

    # Standard Deviation size of flow in forward direction in the window
    std_len_fwd = std(fwd_flows_size)

    # Standard Deviation size of flow in backward direction in the window
    std_len_bwd = std(bwd_flows_size)

    # Time between 2 flows in the window in the forward direction
    time_interval_fwd = []
    if total_fwd == 0 or total_fwd == 1:
        time_interval_fwd = [0]
    else:
        timestamps = [__str_to_timestamp(i[__get_feature_index('time')]) for i in fwd_flows]
        for i in range(len(timestamps) - 1):
            time_interval_fwd.append(abs(timestamps[i+1]-timestamps[i]))

    # Time between 2 flows in the window in the backward direction
    time_interval_bwd = []
    if total_bwd == 0 or total_bwd == 1:
        time_interval_bwd = [0]
    else:
        timestamps = [__str_to_timestamp(i[__get_feature_index('time')]) for i in bwd_flows]
        for i in range(len(timestamps) - 1):
            time_interval_bwd.append(abs(timestamps[i+1]-timestamps[i]))

    # Number of times a PSH flag was set in flows in the window in the forward direction
# !!
    fwd_psh_cnt=sum([i[__get_feature_index('fwd psh')] for i in fwd_flows])

    # Number of times a PSH flag was set in flows in the window in the backward direction
    bwd_psh_cnt = sum([i[__get_feature_index('bwd psh')] for i in bwd_flows])

    # Number of times a URG flag was set in flows in the window in the forward direction
    fwd_psh_cnt = sum([i[__get_feature_index('fwd urg')] for i in fwd_flows])
    
    # Number of times a URG flag was set in flows in the window in the backward direction
    bwd_psh_cnt = sum([i[__get_feature_index('bwd psh')] for i in bwd_flows])

    # Total bytes used in headers in the forward direction in the window
    fwd_header_len = sum([i[__get_feature_index('fwd header')] for i in fwd_flows] + [i[__get_feature_index('bwd header')] for i in bwd_flows])
    
    # Total bytes used in headers in the backward direction in the window
    bwd_header_len = sum([i[__get_feature_index('bwd header')] for i in fwd_flows] + [i[__get_feature_index('fwd header')] for i in bwd_flows])

    # Number of flows in the window with FIN flag
    sum(df_in[cols_inuse[__get_feature_index('fin')]])
    # Number of flows in the window with RST flag
    sum(df_in[cols_inuse[__get_feature_index('rst')]])
    # Number of flows in the window with SYN flag
    sum(df_in[cols_inuse[__get_feature_index('syn')]])
    # Number of flows in the window with PUSH flag
    sum(df_in[cols_inuse[__get_feature_index('push')]])
    # Number of flows in the window with ACK flag
    sum(df_in[cols_inuse[__get_feature_index('ack')]])
    # Number of flows in the window with URG flag
    sum(df_in[cols_inuse[__get_feature_index('urg')]])
    # Number of flows in the window with CWE flag
    sum(df_in[cols_inuse[__get_feature_index('cwe')]])
    # Number of flows in the window with ECE flag
    sum(df_in[cols_inuse[__get_feature_index('ece')]])
    return time_interval_fwd

def __str_to_timestamp(str_time):
    # datetime_object = datetime.strptime('2018-12-01 10:51:39.820842', '%Y-%m-%d %H:%M:%S.%f')
    return datetime.strptime(str_time, '%Y-%m-%d %H:%M:%S.%f').timestamp()


def __get_feature_index(name):
    name = name.upper()
    general_tag = False  # Flow id, source prot, ...
    direction_tag = False  # Fwd, Bwd
    flag_tag = False  # FIN, SYN, ...
    type_tag = False  # Total, max, min, ...
    header_tag = False  # T/F if referred header

    available_flags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE"]
    for i in available_flags:
        if i in name:
            flag_tag = i
    if "PUSH" in name: flag_tag = "PSH"

    if re.match(".*FO.*W.*D.*", name) or re.match(".*FWD.*", name):
        direction_tag = "FWD"
    if re.match(".*BACK.*", name) or re.match(".*BWD.*", name) or re.match(".*BACK.*", name):
        direction_tag = "BWD"

    if re.match(".*TOTA.*", name):
        type_tag = "TOT"
    if re.match(".*MAX.*", name):
        type_tag = "MAX"
    if re.match(".*MIN.*", name):
        type_tag = "MIN"
    if re.match(".*AVG.*", name) or re.match(".*AVERA.*", name) or re.match(".*(MEAN )|( MEAN).*", name):
        type_tag = "MEAN"
    if re.match(".*STAND.*", name) or re.match(".*STD.*", name):
        type_tag = "STD"

    if re.match(".*Flow.*ID.*", name):
        general_tag = "Flow ID"
    if re.match(".*S.*RC.*IP.*", name):
        general_tag = "Source IP"
    if re.match(".*D.*S.*T.*ID.*", name):
        general_tag = "Destination IP"
    if re.match(".*D.*S.*T.*PORT.*", name):
        general_tag = "Destination Port"
    if re.match(".*PRO.*", name):
        general_tag = "Protocol"
    if re.match(".*TIME.*", name):
        general_tag = "Timestamp"
    if re.match(".*DUR.*", name):
        general_tag = "Flow Duration"
    if re.match(".*LBL.*", name) or re.match(".*LABEL.*", name):
        general_tag = "LABEL"

    header_tag = re.match(".*HEA.*", name) is not None
    result = []
    for col_name in cols_inuse:
        if general_tag and not general_tag.upper() in col_name.upper():
            continue
        if direction_tag and not direction_tag.upper() in col_name.upper():
            continue
        if flag_tag and not flag_tag.upper() in col_name.upper():
            continue
        if type_tag and not type_tag.upper() in col_name.upper():
            continue
        if header_tag and not "HEADER" in col_name.upper():
            continue
        result.append(col_name)

    if not (re.match(".*SIZE.*", name) or re.match(".*LEN.*", name)) and not header_tag:
        result = [item for item in result if not "Length" in item]
    else:
        result = [item for item in result if "Length" in item]
    if flag_tag:
        if direction_tag:
            result = [item for item in result if not re.match(".*CNT.*", item.upper()) and not re.match(".*COUNT.*", item.upper())]
        else:
            result = [item for item in result if re.match(".*CNT.*", item.upper()) or re.match(".*COUNT.*", item.upper())]

    if len(result) == 0:
        raise KeyError("No such column as", name)
    elif len(result) != 1:
        raise ValueError("Result is too vague, give more detailed keywords,", result)
    else:
        return cols_inuse.index(result[0])
