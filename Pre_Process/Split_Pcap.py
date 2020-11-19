import time
import dpkt
import collections  # 有序字典
import os

def split_by_packet(path_src, path_des, new_file_name, packet_list):
    '''
    按包序号分割pcap
    :param path_src:源文件路径
    :param path_des:目标路径
    :param new_file_name: 生成的pcap文件名
    :param packet_list: 包序号列表
    :return: None
    '''
    start = time.time()
    packet_list = packet_list[:5] #只取前10000个包
    if packet_list == []:
        return 0

    f = open(path_src, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)  # 似乎有问题，目前只能读取pcap

    all_pcap_data = collections.OrderedDict()  # 有序字典
    pkt = 0
    index = 0
    length = len(packet_list) - 1
    # print("reading:", path_src)
    f_new = open(os.path.join(path_des,new_file_name), 'wb')
    writer = dpkt.pcap.Writer(f_new)
    for (ts, buf) in pcap:
        try:
            if index > length:
                break
            pkt += 1
            eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
            # ip = eth.data
            if pkt == packet_list[index]:
                writer.writepkt(pkt=eth, ts=ts)
                index += 1
            # all_pcap_data[ts] = ip  # 将时间戳与应用层负载按字典形式有序放入字典中，方便后续分析.
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    f_new.close()
    end = time.time()
    # print("processing time:%.2f seconds" %(end - start))
    if index > 0:
        return True
    else:
        return False
