from pcap_splitter.splitter import PcapSplitter
import os
import dpkt


def get_tcp(path, path_0, path_2):
    '''
    按规则对pcap进行分割
    :param path: 要分割的pcap文件目录
    :param path_0: 分割后的pcap文件存放目录
    :param path_2:  pcapsplitter.exe的路径
    :return:
    '''
    ps = PcapSplitter(path, path_2 + "PcapSplitter.exe")
    if not os.path.exists(path_0 + "\\tcp"):
        os.mkdir(path_0 + "\\tcp")
    print('splitting...', ps.split_by_session(path_0 + "\\tcp", "tcp"))


def read_tcp(file_path):
    f = open(file_path, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)  # 似乎有问题，目前只能读取pcap

    print("reading:", file_path)
    flag1 = False
    flag2 = False
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
            ip = eth.data
            temp = bin(ip.tcp.flags)
            if temp[-2] == '1':
                flag1 = True
            if temp[-1] == '1':
                flag2 = True

        except Exception as err:
            print("[error] %s" % err)
    f.close()
    return flag1 and flag2


if __name__ == "__main__":
    path = 'D:\\协议逆向\\原始zip\\tcp_raw\\'
    path_0 = 'D:\\协议逆向\\原始zip\\tcp_raw\\'
    path_2 = 'D:\\Setups\\pcapplusplus-19.12-windows-mingw-w64-gcc-6.3.0\\examples\\'

    filelist = os.listdir(path)
    for file in filelist:
        get_tcp(path + file, path_0, path_2)

    filelist = os.listdir(path + 'tcp')
    for file in filelist:
        if not read_tcp(path + 'tcp\\' + file):
            os.remove(path + 'tcp\\' + file)
