import dpkt
import collections  # 
import time
import Bin_Traffic_Analysis.gl

def ReadPcapHex(file_path,numspackets=3):
    '''
    读pcap文件的包的载荷并输出十六进制序列
    :param file_path: 路径
    :return: OrderedDict： key：count value：每个报文应用层前read-length长度的十六进制报文
    '''
    f = open(file_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    all_pcap_data=collections.OrderedDict() # 有序字典,存十六进制形式
    count = 0
    
    print("reading:" , file_path)
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf) 
            if not isinstance(eth.data, dpkt.ip.IP): 
                print(count)
                continue
            ip = eth.data
            transf_data = ip.data 
            if not len(transf_data.data): 
                continue
            count += 1
            all_pcap_data[count] = transf_data.data.hex()
            # if count>1000:
            #     break
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    print("读取的包总数为：", count)
    return all_pcap_data

def ReadPcaps(files_path,numspackets=3):
    all_pcap_data=collections.OrderedDict() # 有序字典,存十六进制形式
    sports=set()# 客户端端口
    dports=set()# 服务器端口
    count = 0
    for file_path in files_path:
        f = open(file_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
        index=0
        sip=0
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf) 
                if not isinstance(eth.data, dpkt.ip.IP): 
                    print(count)
                    continue
                ip = eth.data
                s=ip
                transf_data = ip.data 
                if not len(transf_data.data): 
                    continue
                if sip==0:
                    sip=ip.src
                if sip==ip.src:
                    sports.add(transf_data.sport)
                    dports.add(transf_data.dport)
                else:
                    sports.add(transf_data.dport)
                    dports.add(transf_data.sport)
                count += 1
                index+=1
                if index not in all_pcap_data.keys():
                    # all_pcap_data[index] = [transf_data.data.hex()]
                    all_pcap_data[index] = [transf_data.data]
                else:
                    # all_pcap_data[index].append(transf_data.data.hex())
                    all_pcap_data[index].append(transf_data.data)
                    # all_pcap_data[index] = [transf_data.data.hex()]
                if index==numspackets:
                    break
            except Exception as err:
                print("[error] %s" % err)
        f.close()
    print("读取的包总数为：", count)
    return all_pcap_data ,sports,dports

def ReadAllPcap(files_path,numspackets=3):# 所有流前三个包
    all_pcap_data=collections.OrderedDict() # 有序字典,存十六进制形式
    count = 0

    for file_path in files_path:
        f = open(file_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
        data=collections.OrderedDict()# 分流
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf) 
                if not isinstance(eth.data, dpkt.ip.IP): 
                    print(count)
                    continue
                ip = eth.data
                transf_data = ip.data 
                if not len(transf_data.data): 
                    continue
                if ip.src < ip.dst:
                    key=str(ip.src)+str(transf_data.sport)+str(ip.dst)+str(transf_data.dport)+str(ip.p)
                else:
                    key=str(ip.dst)+str(transf_data.dport)+str(ip.src)+str(transf_data.sport)+str(ip.p)
                if key not in data.keys():
                    data[key]=[transf_data.data.hex()]
                else:
                    data[key].append(transf_data.data.hex())
            except Exception as err:
                print("[error] %s" % err)
        for key in data.keys():
            if len(data[key])<20:
                continue
            for i in range(numspackets):
                k=i+1
                if k not in all_pcap_data.keys():
                    all_pcap_data[k]=[data[key][i]]
                else:
                    all_pcap_data[k].append(data[key][i])
                count+=1
        f.close()
    print("读取的包总数为：", count)
    return all_pcap_data 


