import dpkt
import collections  # 有序字典
import time

def read_pcap_1(file_path, read_length, pkt_num):
    '''
    读pcap文件的包的载荷并输出比特流
    :param file_path: 路径
    :param read_length: 想要读取的长度(bytes)
    :param pkt_num: 从第几个有传输层的包开始读
    :return:
    '''
    f = open(file_path, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f) # 似乎有问题，目前只能读取pcap

    all_pcap_data=collections.OrderedDict() # 有序字典
    all_pcap_data_bin=collections.OrderedDict() # 有序字典,存十六进制形式
    total_len = 0
    pkt = 0
    print("reading:" , file_path)
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf) # 解包，物理层
            if not isinstance(eth.data, dpkt.ip.IP): # 解包，网络层，判断网络层是否存在，
                continue
            ip = eth.data
            # if not isinstance(ip.data, dpkt.tcp.TCP): # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
            #     continue
            # if not isinstance(ip.data, dpkt.udp.UDP):# 解包，判断传输层协议是否是UDP
            #     continue

            transf_data = ip.data # 传输层负载数据，基本上分析流量的人都是分析这部分数据，即应用层负载流量
            if not len(transf_data.data): # 如果应用层负载长度为0，即没有负载，则丢弃
                continue
            pkt += 1
            if pkt < pkt_num:
                continue
            all_pcap_data[ts] = transf_data.data # 将时间戳与应用层负载按字典形式有序放入字典中，方便后续分析.
            total_len += len(all_pcap_data[ts])
            if total_len > read_length:
                break
            all_pcap_data_bin[ts] = hex_2_bin(transf_data.data.hex())
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    # 验证结果，打印保存的数据包的抓包以及对应的包的应用层负载长度
    test_ts = 0
    for ts,app_data in all_pcap_data.items():
        print(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(ts)) ,":",len(app_data))# 将时间戳转换成日期
        test_ts = ts
    # 打印最后一个包的十六进制形式，因为加密数据在命令行打印会出现大量乱码和错行，故在此不做演示打印包的字符形式
    print("总长度为:", total_len, "bytes")
    # print("最后一个包负载的十六进制******")
    # print(len(all_pcap_data_hex[test_ts]))
    # print(all_pcap_data_hex[test_ts])

    return all_pcap_data_bin

def read_pcap_2(file_path, read_pkt = 10000):
    '''
    读pcap文件的包的载荷并输出比特流
    :param file_path: 路径
    :param read_pkt: 想要读取几个包
    :return:
    '''
    f = open(file_path, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)

    all_pcap_data=collections.OrderedDict() # 有序字典
    all_pcap_data_hex=collections.OrderedDict() # 有序字典,存十六进制形式
    count = 0
    total_pkt = 0
    total_len = 0
    print("reading:", file_path)
    for (ts, buf) in pcap:
        try:
            count += 1
            eth = dpkt.ethernet.Ethernet(buf) # 解包，物理层
            if not isinstance(eth.data, dpkt.ip.IP): # 解包，网络层，判断网络层是否存在，
                continue
            ip = eth.data
            # if not isinstance(ip.data, dpkt.tcp.TCP): # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
            #     continue
            # if not isinstance(ip.data, dpkt.udp.UDP):# 解包，判断传输层协议是否是UDP
            #     continue

            transf_data = ip.data # 传输层负载数据，基本上分析流量的人都是分析这部分数据，即应用层负载流量
            if not len(transf_data.data): # 如果应用层负载长度为0，即没有负载，则丢弃
                continue
            total_pkt += 1
            if total_pkt > read_pkt:
                break
            all_pcap_data[count] = transf_data.data # 将时间戳与应用层负载按字典形式有序放入字典中，方便后续分析.
            total_len += len(all_pcap_data[count])
            all_pcap_data_hex[count] = transf_data.data.hex()
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    # 验证结果，打印保存的数据包的抓包以及对应的包的应用层负载长度
    # test_ts = 0
    # for ts,app_data in all_pcap_data.items():
    #     print(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(ts)) ,":",len(app_data))# 将时间戳转换成日期
    #     test_ts = ts
    # 打印最后一个包的十六进制形式，因为加密数据在命令行打印会出现大量乱码和错行，故在此不做演示打印包的字符形式
    # print("总长度为:", total_len, "bytes")
    # print("最后一个包负载的十六进制******")
    # print(len(all_pcap_data_hex[test_ts]))
    # print(all_pcap_data_hex[test_ts])

    return all_pcap_data_hex


def get_port(file_path):
    '''
        读pcap文件(单流)
        :param file_path: 路径
        :param read_pkt: 想要读取几个包
        :return:流的端口号
        '''
    f = open(file_path, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)
    # print("reading:", file_path)
    des_port = 0
    src_port = 0
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
            if not isinstance(eth.data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP): # 传输层协议是TCP
                des_port = ip.data.dport
                src_port = ip.data.sport
                break
            if isinstance(ip.data, dpkt.udp.UDP):# 判断传输层协议是UDP
                des_port = ip.data.dport
                src_port = ip.data.sport
                break
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    return des_port, src_port


def hex_2_bin(str):
    bin = ''
    for i in str:
        if i == '0':
            bin += '0000'
        elif i == '1':
            bin += '0001'
        elif i == '2':
            bin += '0010'
        elif i == '3':
            bin += '0011'
        elif i == '4':
            bin += '0100'
        elif i == '5':
            bin += '0101'
        elif i == '6':
            bin += '0110'
        elif i == '7':
            bin += '0111'
        elif i == '8':
            bin += '1000'
        elif i == '9':
            bin += '1001'
        elif i == 'a':
            bin += '1010'
        elif i == 'b':
            bin += '1011'
        elif i == 'c':
            bin += '1100'
        elif i == 'd':
            bin += '1101'
        elif i == 'e':
            bin += '1110'
        else:
            bin += '1111'
    return bin


if __name__ == '__main__':
    file_path = "D:\\Program Files\\Wireshark\\test.pcap"
    s = read_pcap_2(file_path)
    print(s)
