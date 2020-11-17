import struct
import time
import dpkt
import collections  # 有序字典


# def split_by_packet(path_src, path_des, new_file_name, packet_list):
#     '''
#     按包序号分割pcap
#     :param path_src:源文件路径
#     :param path_des:目标路径
#     :param new_file_name: 生成的pcap文件名
#     :param packet_list: 包序号列表
#     :return: None
#     '''
#     start = time.time()
#     packet_list = packet_list[:5] #只取前10000个包
#     if packet_list == []:
#         return 0
#     fpcap = open(path_src, 'rb')
#     string_data = fpcap.read()
#
#     '''
#     pcap_header = {}
#     pcap_header['magic_number'] = string_data[0:4]
#     pcap_header['version_major'] = string_data[4:6]
#     pcap_header['version_minor'] = string_data[6:8]
#     pcap_header['thiszone'] = string_data[8:12]
#     pcap_header['sigfigs'] = string_data[12:16]
#     pcap_header['snaplen'] = string_data[16:20]
#     pcap_header['linktype'] = string_data[20:24]
#     '''
#     file_header = string_data[0:24]
#
#     packet_num = 1
#     pcap_packet_header = {}
#
#     i = 24
#     with open(path_des + new_file_name, 'ab+') as f:
#         new_content = file_header
#         while(i < len(string_data)):
#             # 数据包头各个字段
#             pcap_packet_header['GMTtime'] = string_data[i:i+4]
#             pcap_packet_header['MicroTime'] = string_data[i+4:i+8]
#             pcap_packet_header['caplen'] = string_data[i+8:i+12]
#             pcap_packet_header['len'] = string_data[i+12:i+16]
#             packet_header = string_data[i:i+16]
#             # 求出此包的包长len
#             packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
#             # 写入此包数据
#             if packet_num in packet_list:
#                 new_content += packet_header
#                 new_content += string_data[i+16:i+16+packet_len]
#                 if packet_num == packet_list[-1]:
#                     break
#                 # print(string_data[i+16:i+16+packet_len].hex())
#             i = i + packet_len + 16
#             packet_num += 1
#         f.write(new_content)
#         f.close()
#     end = time.time()
#     print("processing time:%.2f seconds" %(end - start))



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
    print("reading:", path_src)
    f_new = open(path_des + new_file_name, 'wb')
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
    print("processing time:%.2f seconds" %(end - start))
    if index > 0:
        return True
    else:
        return False


if __name__ == "__main__":
    src = "D:\\协议逆向\\filter\\filter_app_flow\\pptv_mobile\\0-0006.pcap"
    des = "D:\\协议逆向\\filter\\filter_app_flow\\pptv_mobile\\"
    split_by_packet(src, des, "test.pcap", [4,6,7,9])
