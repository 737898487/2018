from cluster.ngram import n_gram_matrix
from cluster.feature import *
from libs.new_preprocess import *
import os
import dpkt
from libs.packet_recombination import write_biflow_to_file


def parse(src_path, dst_path, remove, flow_packets):
    if not os.path.exists(os.path.join(dst_path, "text_udp")):
        os.mkdir(os.path.join(dst_path, "text_udp"))
    if not os.path.exists(os.path.join(dst_path, "text_tcp")):
        os.mkdir(os.path.join(dst_path, "text_tcp"))
    if not os.path.exists(os.path.join(dst_path, "bin_udp")):
        os.mkdir(os.path.join(dst_path, "bin_udp"))
    if not os.path.exists(os.path.join(dst_path, "bin_tcp")):
        os.mkdir(os.path.join(dst_path, "bin_tcp"))

    file_list = ["bin_tcp", "text_tcp", "bin_udp", "text_udp"]
    # 先切分pcap,得到业务流
    ps = PreProcess()
    ps.read_pcap_divide(src_path, 0.8)
    flow_bin_text = ps.get_element()
    num = -1
    for ele in flow_bin_text:
        num += 1
        new_dst_path = os.path.join(dst_path, file_list[num])
        if len(ele) == 0:
            continue
        pcap_data = convert(ele, length=30)

        # 聚类预处理
        if num == 0 or num == 2: # 只对二进制聚类
            matrix = n_gram_matrix(pcap_data, 2)
            fea_vec = GetFeaVet(matrix, len(pcap_data), threshold=0.1)
            X = GetAllVet(pcap_data, fea_vec, port_weight=10)
            clu_list = Clusters(pcap_data, X)
        else:
            clu_list = [0] * len(pcap_data)

        for i in range(len(clu_list)):
            if not os.path.exists(os.path.join(new_dst_path, str(clu_list[i]))):
                os.mkdir(os.path.join(new_dst_path, str(clu_list[i])))
            work_path = os.path.join(new_dst_path, str(clu_list[i]))
            f_new = open(work_path + '\\' + str(i) + '.pcap', 'wb')
            writer = dpkt.pcap.Writer(f_new)
            temp_count = 0
            for p in ele[i][1]:
                temp_count += 1
                if temp_count > flow_packets:
                    break
                writer.writepkt(pkt=p[1], ts=p[0])
            f_new.close()
            # 去重传
            if remove:
                write_biflow_to_file(work_path + '\\' + str(i) + '.pcap')

if __name__ == '__main__':
    path = "D:\\协议逆向\\原始zip\\新建文件夹\\手机淘宝android1-100"
    dst_path = "D:\\协议逆向\\原始zip\\新建文件夹\\used"

    parse(path, dst_path, False, 100)
