# Machine-Learning-DDoS
CSI4900 Project, DDoS detection using machine learning
## Features
Detect DDoS attack traffic using a machine learning method.<br>
Giving network traffic of a period and tells whether the remote host is committing DDoS attack.

## Repo data structure
Machine-Learning-DDoS<br>
&emsp;|&#8722;&#8722;sr&emsp;&emsp;&emsp;&emsp;Code of this project<br>
&emsp;|&#8722;&#8722;Dataset&emsp;&emsp;&emsp;The dataset used for training and testing<br>
&emsp;|&#8722;&#8722;Paper&emsp;&emsp;&emsp;&emsp;Paper and summery of realated work<br>

## Dataset
[CICDDoS2019 from UNB](https://www.unb.ca/cic/datasets/ddos-2019.html)<br>
This dataset provides a large set of attack traffic with different types, the type of attack was labeled in the CSV file.<br>
In Github, only first 200k records of each type of attack were uploaded. Rest of the data could be downloaded from the link of the dataset.

## Type of attack
In the dataset, the following types of DDoS were provided.<br>
DNS, LDAP, MSSQL, NetBIOS, NTP, PortMap, SNMP, SSDP, SYN, TFTP, UDP, UDP-Lag

## Training method(Techniques)
Multilayer Perceptron, random forest, Naive Bayes, K-nearest neighbors
