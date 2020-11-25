import os
import Bin_Traffic_Analysis.Read_Pcap as readpcap
import Bin_Traffic_Analysis.Bin_Traffic_Parse
import Bin_Traffic_Analysis.Needleman as Needleman
import threading 
import multiprocessing  
import Bin_Traffic_Analysis.Extract_Feature as Extract
import collections
import Bin_Traffic_Analysis.Global_Var
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Executor
import warnings


def Bin_Re(data_input,name):
    warnings.filterwarnings("ignore")
    # data path
    if not os.path.exists("./result"):
        os.mkdir("./result")
    app=name

    files_tcp=os.listdir(data_input+"/bin_tcp")
    for i in range(len(files_tcp)):
        files_tcp[i]=data_input+"/bin_tcp/"+files_tcp[i]
    files_udp=os.listdir(data_input+"/bin_udp")
    for i in range(len(files_udp)):
        files_udp[i]=data_input+"/bin_udp/"+files_udp[i]
    files=files_udp+files_tcp

    if len(files) == 0:
        print('No bin data')
        return

    data=dict()
    sports=set()
    dports=set()
    for i in range(len(files)):# 
        pcaps_name=os.listdir(files[i])
        for j in range(len(pcaps_name)):
            pcaps_name[j]=files[i]+"/"+pcaps_name[j]
        # if len(pcaps_name)>20:
        data[files[i]],sport,dport=readpcap.ReadPcapsSplice(pcaps_name,3)
        sports=sport|sports
        dports=dport|dports
    
    application=Extract.Application(app,data,sports,dports)
    application.setTraffic()
    application.setTrafficFea(True)
    application.tojson()

