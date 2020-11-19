#!/usr/bin/python
#coding:utf-8
import os
import Re.readpcap as readpcap
import Re.parse
import Re.Needleman as Needleman
import threading 
import multiprocessing  
import Re.Extract as Extract 
import collections
import Re.gl
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

def BinRe(data_input):
    warnings.filterwarnings("ignore")
    # data path
    app=data_input.split("/")[-1]
    # data_input="./data/"+app
    files_tcp=os.listdir(data_input+"/bin_tcp")
    for i in range(len(files_tcp)):
        files_tcp[i]=data_input+"/bin_tcp/"+files_tcp[i]
    files_udp=os.listdir(data_input+"/bin_udp")
    for i in range(len(files_udp)):
        files_udp[i]=data_input+"/bin_udp/"+files_udp[i]
    files=files_udp+files_tcp

    data=dict()
    for i in range(len(files)):# 
        pcaps_name=os.listdir(files[i])
        for j in range(len(pcaps_name)):
            pcaps_name[j]=files[i]+"/"+pcaps_name[j]
        # get data
        # data[files[i]]=readpcap.ReadAllPcap(pcaps_name,3)
        if len(pcaps_name)>20:
            data[files[i]],sports,dports=readpcap.ReadPcaps(pcaps_name,3)
    application=Extract.Application(app,data,sports,dports)
    application.setTraffic()
    application.setTrafficFea(True)
    application.tojson()
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

if __name__ == "__main__":
    # files=os.listdir("./Re/NewData")
    # for i in range(len(files)):
        # files[i]="./Re/NewData/"+files[i]
        # BinRe(files[i])
    BinRe("./Re/NewData/smb")
    # print(gl.sum)