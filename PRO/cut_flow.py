from pcap_splitter.splitter import PcapSplitter
import os
from libs.read_pcap import get_port


def pcap_flow_cut(path, path_0, path_2, pkt_count = 10000):
    '''
    按规则对pcap进行分割
    :param path: 要分割的pcap文件目录
    :param path_0: 分割后的pcap文件存放目录
    :param path_2:  pcapsplitter.exe的路径
    :param pkt_count:  取前count个包
    :return:
    '''
    ps = PcapSplitter(path, path_2 + "PcapSplitter.exe")
    if not os.path.exists(path_0 + "\\up"):
        os.mkdir(path_0 + "\\up")
    if not os.path.exists(path_0 + "\\down"):
        os.mkdir(path_0 + "\\down")
    des_port, src_port = get_port(path)
    print(ps.split_by_count(pkt_count, path_0 + "\\up", "dst port " + str(des_port)))
    print(ps.split_by_count(pkt_count, path_0 + "\\down", "dst port " + str(src_port)))
    return 0


if __name__ == "__main__":
    path = "D:\\协议逆向\\filter\\filter_app_flow\\wzry"
    path_0 = path
    path_2 = 'D:\\Setups\\pcapplusplus-19.12-windows-mingw-w64-gcc-6.3.0\\examples\\'
    folderlist = os.listdir(path)
    try:
        for folder in folderlist:
            filelist = os.listdir(path + "\\" + folder)
            for file in filelist:
                pcap_flow_cut(path + "\\" + folder + "\\" + file, path_0 + "\\" + folder, path_2)
    except Exception as e:
        for file in folderlist:
            pcap_flow_cut(path + "\\" + file,path_0, path_2)