import dpkt
import collections  # 有序字典


def get_pcap_time(file_path):
    '''
    读pcap文件,返回pcap的持续时间
    :param file_path: 路径
    :return: duration: 持续时间
    '''
    f = open(file_path, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)  # 有问题，目前只能读取pcap

    all_pcap_data = collections.OrderedDict()  # 有序字典
    # print("reading:" , file_path)
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
            if not isinstance(eth.data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                continue
            ip = eth.data
            transf_data = ip.data
            if not len(transf_data.data):
                continue
            all_pcap_data[ts] = transf_data.data  # 将时间戳与应用层负载按字典形式有序放入字典中
        except Exception as err:
            print("[error] %s" % err)
    f.close()
    try:
        duraion = list(all_pcap_data.keys())[-1] - list(all_pcap_data.keys())[0]
        return duraion
    except:
        return 0


if __name__ == "__main__":
    path = 'D:\\协议逆向\\filter\\filter_app_flow\\pubg\\TslGame.exe_14068-0012.pcap'
    get_pcap_time(path)
