#!/usr/bin/python
#coding:utf-8
import os
import readpcap
import parse
import Needleman
import threading 
import multiprocessing  
import Extract
import collections
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Executor
import warnings


def MultiprocessingNeedleman(key,seqs):

    if len(seqs)>1 :
        res_seqs=Needleman.Needleman(seqs)
        # if (f=open("./result/"+str(key),'w+')):
        with open("./result/"+str(key),'w') as f:
            for seq in res_seqs:
                print(seq)
                f.write(seq+"\n")
        f.close()
            # print("error")
        
        # for seq in res_seqs:
        #     f.write(seq+"\n")

    return

def BinRe(data_input)
    warnings.filterwarnings("ignore")
    # data path
    # app="mrzh"
    # data_input="./data/"+app
    files=os.listdir(data_input)
    data=dict()
    for i in range(len(files)):# 
        files[i]=data_input+"/"+files[i]
        pcaps_name=os.listdir(files[i])
        for j in range(len(pcaps_name)):
            pcaps_name[j]=files[i]+"/"+pcaps_name[j]
        # get data
        # data[files[i]]=readpcap.ReadAllPcap(pcaps_name,3)
        data[files[i]],sports,dports=readpcap.ReadPcaps(pcaps_name,3)
    application=Extract.Application(app,data,sports,dports)
    application.setTraffic()
    application.setTrafficFea(True)
    # application.tojson()
    # data_path="./data/smb.pcap"
    # # files=os.listdir(data_path)
    # # for i in range(len(files)):
    # #     files[i]=data_path+"/"+files[i]
    # #readpcap
    # pcap_data=readpcap.ReadPcapHex(data_path)
    # # pcap_data,sports,dports=readpcap.ReadPcaps(files,1)

    # # parse
    # res=parse.Parse(pcap_data,0)

    # #concurrent Needleman 
    # conPool=ProcessPoolExecutor()
    # for key in res.keys():
    #     out=open("./result/Row"+str(key),'w')
    #     for seq in res[key]:
    #         out.write(seq+"\n")
    #     out.close()
    #     conPool.submit(MultiprocessingNeedleman,key,res[key])
    # conPool.shutdown(True)