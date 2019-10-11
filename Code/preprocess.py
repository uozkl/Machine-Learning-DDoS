import pandas as pd
import sys
import re
from collections.abc import Iterable

'''
if len(sys.argv) <2:
    path = input("No path arg, input path:\n")
else:
    path = sys.argv[1]
'''
# Test file path
path = "D:/test.pcap_Flow.csv"

# List of columns without unsed data, CIC meter use a different naming method in the later version
# For most of the labels in the old version, there are a space in front of them
csv_col_new = [
    'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
    'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
    'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Fwd Header Len',
    'Bwd Header Len', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
    'ECE Flag Cnt', 'Label'
]
unused_csv_col_new = [
    'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
    'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]
csv_col_old = [
    'Flow ID', ' Source IP', ' Source Port', ' Destination IP',
    ' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration',
    ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean', ' Bwd Packet Length Std', ' Fwd Header Length',
    ' Bwd Header Length', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags',
    ' Bwd URG Flags', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count',
    ' ECE Flag Count', ' Label'
]
unused_csv_col_old = [
    'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std',
    ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
    ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total',
    ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length',
    ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
    ' Packet Length Variance', ' Down/Up Ratio', ' Average Packet Size',
    ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', ' Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
    ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
    ' Subflow Bwd Bytes', 'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std',
    ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max',
    ' Idle Min', 'SimillarHTTP', ' Inbound'
]

# Column data type
csv_col_datatype = {
    "Protocol": "int8",
    "Dst Port": "uint16",
    "Destination Port": "uint16",
    "Source Port": "uint16",
    "Src Port": "uint16"
}

# Read file
encoding_type = "utf-8"
cols_inuse = csv_col_old
while (True):
    try:
        df = pd.read_csv(
            path,
            low_memory=False,
            encoding=encoding_type,
            dtype=csv_col_datatype,
            usecols=csv_col_new)
        break
    except FileNotFoundError:
        path = input("CSV path error, input the path of the netflow csv file")
    except UnicodeDecodeError as e:
        if encoding_type == "utf-8":
            encoding_type = "ISO-8859-1"
        else:
            raise e
    except ValueError as e:
        if cols_inuse == csv_col_old:
            cols_inuse = csv_col_new
        else:
            raise e


# Getter
def __get_feature_tags(name):
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
    if "PUSH" in available_flags: flag_tag = "PSH"

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

    return [general_tag, direction_tag, flag_tag, type_tag, header_tag]


def get_feature_index(name):
    general_tag, direction_tag, flag_tag, type_tag, header_tag = __get_feature_tags(name)
    result = []
    for col_name in cols_inuse:
        if general_tag and not general_tag in col_name.upper():
            continue
        if direction_tag and not direction_tag in col_name.upper():
            continue
        if flag_tag and not flag_tag in col_name.upper():
            continue
        if type_tag and not type_tag in col_name.upper():
            continue
        if header_tag and not "HEADER" in col_name.upper():
            continue
        result.append(col_name)
    if len(result) == 0:
        raise KeyError("No such column as", name)
    elif len(result) != 1:
        raise ValueError("Result is too vague, give more detailed keywords,", result)
    else:
        return cols_inuse.index(result[0])


def get_feature(name, source=None):
    '''
    Example:
        get_feature("Time"), return a sub dataframe of the whole column
        get_feature(["FIN cnt", "Time"]), return a sub dataframe of two columns
        get_feature("Time", df.values[2]), return the exact value of the block of that ndarray
        get_feature("Time", 5), return the exact value of the block of row 6
        get_feature(["FIN cnt", "Time"], 5), return a list of value of the block of row 6
    '''
    if not isinstance(name, Iterable):
        name = [name]
    name_index = [get_feature_index(n) for n in name]
    if source is None:
        return df[[cols_inuse[n] for n in name_index]]
    if isinstance(source, int):
        return [df.values[source][n] for n in name_index]
    return [source[n] for n in name_index]