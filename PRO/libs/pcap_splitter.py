import dpkt
import os
from .packet_recombination import write_biflow_to_file
# import heapq


class Ququadruple:
    def __init__(self, src, dst, src_port, dst_port):
        self.ip_src = src
        self.ip_dst = dst
        self.src_port = src_port
        self.dst_port = dst_port

    def __eq__(self, other):
        flag_1 = self.ip_src == other.ip_src and self.ip_dst == other.ip_dst and self.src_port == other.src_port and self.dst_port == other.dst_port
        flag_2 = self.ip_src == other.ip_dst and self.ip_dst == other.ip_src and self.src_port == other.dst_port and self.dst_port == other.src_port
        return flag_1 or flag_2

    def __hash__(self):
        string_qua = str(sorted([self.ip_src, self.ip_dst]) + sorted([self.src_port, self.dst_port]))
        return hash(string_qua)

    def __str__(self):
        return str(int.from_bytes(self.ip_src,'little')) + "_" + str(int.from_bytes(self.ip_dst,'little')) + "_" + str(self.src_port) + "_" + str(self.dst_port)


class PcapSplitter:
    def __init__(self, name = None):
        if name:
            file_path = os.getcwd() + "\\app_json\\" + name + ".json"
            self.config = self.load_json(file_path)[name]
        else:
            self.config = {}
            self.config["tcp_port"] = "All"
            self.config["tcp_flow"] = [-1]
            self.config["udp_port"] = "All"
            self.config["udp_flow"] = [-1]

    def load_json(self, path):
        import json
        """
        支持以//开头的注释
        """
        lines = []
        with open(path) as f:
            for row in f.readlines():
                if row.strip().startswith("//"):
                    continue
                lines.append(row)
        return json.loads("\n".join(lines))


    def split_by_session(self,
                         path_src,
                         path_dst,
                         keep_only_app=False,
                         remove=False,
                         flow_packets=100000):

        f = open(path_src, 'rb')
        try:
            pcap = dpkt.pcap.Reader(f)
        except:
            pcap = dpkt.pcapng.Reader(f)  # 似乎有问题，目前只能读取pcap
        print("reading:", path_src)
        tcp_flow_dict = dict()
        udp_flow_dict = dict()
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
                if not isinstance(eth.data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                    continue
                ip = eth.data
                if keep_only_app:
                    transf_data = ip.data  # 传输层负载数据
                    if not len(transf_data.data):  # 如果应用层负载长度为0，即没有负载，则丢弃
                        continue
                if ip.p == 17: # udp
                    qua = Ququadruple(ip.src, ip.dst, ip.udp.sport, ip.udp.dport)
                    if qua not in udp_flow_dict:
                        udp_flow_dict[qua] = [(ts, eth)]
                    else:
                        udp_flow_dict[qua].append((ts, eth))
                elif ip.p == 6: # tcp
                    qua = Ququadruple(ip.src, ip.dst, ip.tcp.sport, ip.tcp.dport)
                    if qua not in tcp_flow_dict:
                        tcp_flow_dict[qua] = [(ts, eth)]
                    else:
                        tcp_flow_dict[qua].append((ts, eth))
            except Exception as err:
                print("[error] %s" % err)

        src_name = path_src.split('\\')[-1][:-5]

        tcp_list = sorted(tcp_flow_dict.items(), key=lambda x: len(x[1]), reverse=True)
        count_tcp_list = [0]*len(self.config['tcp_port'])
        for flow in tcp_list:
            if self.config['tcp_port'] == 'None':
                break
            if self.config['tcp_port'] == 'All':
                if self.config['tcp_flow'][0] != -1:
                    count_tcp_list[0] += 1
                    if count_tcp_list[0] > self.config['tcp_flow'][0]:
                        break
                if not os.path.exists(path_dst + "\\tcp"):
                    os.mkdir(path_dst + "\\tcp")
                f_new = open(path_dst + "\\tcp\\" + src_name + '_' + str(flow[0]) + '.pcap', 'wb')
                writer = dpkt.pcap.Writer(f_new)
                temp_count = 0
                for p in flow[1]:
                    temp_count += 1
                    if temp_count > flow_packets:
                        break
                    writer.writepkt(pkt=p[1], ts=p[0])
                f_new.close()
                if remove:  # 去重传去乱序
                    write_biflow_to_file(path_dst + "\\tcp\\" + src_name + '_' + str(flow[0]) + '.pcap')
            else:
                for index in range(len(self.config['tcp_port'])):
                    if flow[0].dst_port == self.config['tcp_port'][index] or flow[0].src_port == self.config['tcp_port'][index]:
                        count_tcp_list[index] += 1
                        if count_tcp_list[index] > self.config['tcp_flow'][index]:
                            break
                        if not os.path.exists(path_dst + "\\tcp" + str(index)):
                            os.mkdir(path_dst + "\\tcp" + str(index))
                        f_new = open(path_dst + "\\tcp" + str(index) + "\\" + src_name + '_' + str(flow[0]) + '.pcap', 'wb')
                        writer = dpkt.pcap.Writer(f_new)
                        temp_count = 0
                        for p in flow[1]:
                            temp_count += 1
                            if temp_count > flow_packets:
                                break
                            writer.writepkt(pkt=p[1], ts=p[0])
                        f_new.close()
                        if remove:  # 去重传去乱序
                            write_biflow_to_file(path_dst + "\\tcp" + str(index) + "\\" + src_name + '_' + str(flow[0]) + '.pcap')


        count_udp_list = [0] * len(self.config['udp_port'])
        udp_list = sorted(udp_flow_dict.items(), key=lambda x: len(x[1]), reverse=True)
        for flow in udp_list:
            if self.config['udp_port'] == 'None':
                break
            if self.config['udp_port'] == 'All':
                if self.config['udp_flow'][0] != -1:
                    count_udp_list[0] += 1
                    if count_udp_list[0] > self.config['udp_flow'][0]:
                        break
                if not os.path.exists(path_dst + "\\udp"):
                    os.mkdir(path_dst + "\\udp")
                f_new = open(path_dst + "\\udp\\" + src_name + '_' + str(flow[0]) + '.pcap', 'wb')
                writer = dpkt.pcap.Writer(f_new)
                temp_count = 0
                for p in flow[1]:
                    temp_count += 1
                    if temp_count > flow_packets:
                        break
                    writer.writepkt(pkt=p[1], ts=p[0])
                f_new.close()
            else:
                for index in range(len(self.config['udp_port'])):
                    if flow[0].dst_port == self.config['udp_port'][index] or flow[0].src_port == self.config['udp_port'][index]:
                        count_udp_list[index] += 1
                        if count_udp_list[index] > self.config['udp_flow'][index]:
                            break
                        if not os.path.exists(path_dst + "\\udp" + str(index)):
                            os.mkdir(path_dst + "\\udp" + str(index))
                        f_new = open(path_dst + "\\udp" + str(index) + "\\" + src_name + '_' + str(flow[0]) + '.pcap', 'wb')
                        writer = dpkt.pcap.Writer(f_new)
                        temp_count = 0
                        for p in flow[1]:
                            temp_count += 1
                            if temp_count > flow_packets:
                                break
                            writer.writepkt(pkt=p[1], ts=p[0])
                        f_new.close()
        f.close()


if __name__ == "__main__":
    ps = PcapSplitter("iqiyi")
    path_src = "D:\\协议逆向\\原始zip\\新建文件夹\\爱奇艺_安卓100-149"
    path_dst = "D:\\协议逆向\\原始zip\\新建文件夹\\test"
    # os.mkdir(path_dst + "\\tcp\\")
    # os.mkdir(path_dst + "\\udp\\")
    filepath = os.listdir(path_src)
    for file in filepath:
        ps.split_by_session(os.path.join(path_src, file), path_dst, keep_only_app=True, remove=True,flow_packets=100)