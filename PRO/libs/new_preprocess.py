import dpkt
import os
from bin_text_test.bin_text import printable


class CountQuquadruple:
    def __init__(self, src, dst, src_port, dst_port, count):
        self.ip_src = src
        self.ip_dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.count = count

    def __eq__(self, other):
        flag_1 = self.count == other.count and self.ip_src == other.ip_src and self.ip_dst == other.ip_dst and self.src_port == other.src_port and self.dst_port == other.dst_port
        flag_2 = self.count == other.count and self.ip_src == other.ip_dst and self.ip_dst == other.ip_src and self.src_port == other.dst_port and self.dst_port == other.src_port
        return flag_1 or flag_2

    def __hash__(self):
        string_qua = str(self.count) + str(sorted([self.ip_src, self.ip_dst]) + sorted([self.src_port, self.dst_port]))
        return hash(string_qua)

    def __str__(self):
        return str(self.count) + "_" + str(int.from_bytes(self.ip_src,'little')) + "_" + str(int.from_bytes(self.ip_dst,'little')) + "_" + str(self.src_port) + "_" + str(self.dst_port)


class PreProcess:
    def __init__(self):
        self.text_udp_flow_list = []
        self.text_tcp_flow_list = []
        self.bin_udp_flow_list = []
        self.bin_tcp_flow_list = []

    def read_drop(self, path_src, count, ratio):
        '''
        读取一个pcap并选取其中占比前ratio的流
        :param path_src: pcap源路径
        :param count: pcap编号
        :param ratio: 比例
        :return: None
        '''
        f = open(path_src, 'rb')
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            print(e)
            pcap = dpkt.pcapng.Reader(f)  # 似乎有问题，目前只能读取pcap
        print("reading:", path_src)
        tcp_flow_dict = dict()
        udp_flow_dict = dict()
        tcp_length = 0
        udp_length = 0
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
                if not isinstance(eth.data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                    continue
                ip = eth.data
                transf_data = ip.data  # 传输层负载数据
                if not len(transf_data.data):  # 如果应用层负载长度为0，即没有负载，则丢弃
                    continue
                if ip.p == 17:  # udp
                    udp_length += 1
                    qua = CountQuquadruple(ip.src, ip.dst, ip.udp.sport, ip.udp.dport, count)
                    if qua not in udp_flow_dict:
                        udp_flow_dict[qua] = [(ts, eth)]
                    else:
                        udp_flow_dict[qua].append((ts, eth))
                elif ip.p == 6:  # tcp
                    tcp_length += 1
                    qua = CountQuquadruple(ip.src, ip.dst, ip.tcp.sport, ip.tcp.dport, count)
                    if qua not in tcp_flow_dict:
                        tcp_flow_dict[qua] = [(ts, eth)]
                    else:
                        tcp_flow_dict[qua].append((ts, eth))
            except Exception as err:
                print("[error] %s" % err)

        tcp_list = sorted(tcp_flow_dict.items(), key=lambda x: len(x[1]), reverse=True)
        now_tcp_length = 0
        for flow in tcp_list:
            if len(flow[1]) < 10:
                break
            now_tcp_length += len(flow[1])
            if now_tcp_length / tcp_length > ratio:
                break
            if printable(flow[1][0][1].data.data.data.hex())[1] > 0.9:
                self.text_tcp_flow_list.append(flow)
            else:
                self.bin_tcp_flow_list.append(flow)

        udp_list = sorted(udp_flow_dict.items(), key=lambda x: len(x[1]), reverse=True)
        now_udp_length = 0
        for flow in udp_list:
            if len(flow[1]) < 10:
                break
            now_udp_length += len(flow[1])
            if now_udp_length / udp_length > ratio:
                break
            if printable(flow[1][0][1].data.data.data.hex())[1] > 0.9:
                self.text_udp_flow_list.append(flow)
            else:
                self.bin_udp_flow_list.append(flow)

    def read_pcap_divide(self, src_path, ratio):
        path_list = os.listdir(src_path)
        count = 0
        for path in path_list:
            count += 1
            # if count > 5:
            #     break
            self.read_drop(os.path.join(src_path, path), count, ratio)

    def get_element(self):
        return (self.bin_tcp_flow_list, self.text_tcp_flow_list, self.bin_udp_flow_list, self.text_udp_flow_list)


def convert(flow_list, length):
    hex_list = []
    for flow in flow_list:
        dport = flow[0].dst_port
        count = 0
        each_hex_seq = ''
        for each in flow[1]:  # each:(ts, data)
            if count > 2:
                break
            seq = each[1].data.data.data
            if len(seq) == 0:
                continue
            count += 1
            if len(seq.hex()) < length:
                each_hex_seq += seq.hex()
                each_hex_seq += '0' * (length - len(seq.hex()))
            else:
                each_hex_seq += seq.hex()[0:length]
        hex_list.append((dport, each_hex_seq))
    return hex_list


if __name__ == "__main__":
    test_path = "D:\\协议逆向\\原始zip\\新建文件夹\\手机淘宝android1-100"
    # test_path = "C:\\Users\\kpy\\Desktop\\170.pcap"
    ps = PreProcess()
    # ps.read_drop(test_path)
    ps.read_pcap_divide(test_path, 0.8)
    res = convert(ps.bin_tcp_flow_list, 30)
