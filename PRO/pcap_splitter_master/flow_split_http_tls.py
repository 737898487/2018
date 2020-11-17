from pcap_splitter.splitter import PcapSplitter
import os
from bin_text_main import *
from libs.split_pcap import *


def pcap_flow_split(protocal_name, path, path_0, path_2):
    '''
    按规则对pcap进行分割
    :param protocal_name:
    :param path: 要分割的pcap文件目录
    :param path_0: 分割后的pcap文件存放目录
    :param path_2:  pcapsplitter.exe的路径
    :return:
    '''
    ps = PcapSplitter(path, path_2 + "PcapSplitter.exe")
    if protocal_name == 'http':
        if not os.path.exists(path_0 + "\\http"):
            os.mkdir(path_0 + "\\http")
        print('splitting ' + protocal_name, ps.split_by_session(path_0 + "\\http", "tcp port 80"))
        return 0

    if protocal_name == 'tls':
        if not os.path.exists(path_0 + "\\tls"):
            os.mkdir(path_0 + "\\tls")
        print('splitting ' + protocal_name, ps.split_by_session(path_0 + "\\tls", "tcp port 443"))
        return 0

    if protocal_name == 'ssh':
        if not os.path.exists(path_0 + "\\ssh"):
            os.mkdir(path_0 + "\\ssh")
        print('splitting ' + protocal_name, ps.split_by_session(path_0 + "\\ssh", "tcp port 22"))
        return 0



if __name__ == "__main__":
    path = 'D:\\协议逆向\\原始zip\\TEST\\'
    path_0 = 'D:\\协议逆向\\filter\\'
    path_2 = 'D:\\Setups\\pcapplusplus-19.12-windows-mingw-w64-gcc-6.3.0\\examples\\'
    # 分流
    file_list = os.listdir(path)
    for file in file_list:
        pcap_flow_split('http', path + file, path_0, path_2)
        pcap_flow_split('tls', path + file, path_0, path_2)
    http_file_list = os.listdir(path_0 + 'http')
    for file in http_file_list:
        if os.path.getsize(path_0 + 'http\\' + file) < 1024 :
            os.remove(path_0 + 'http\\' + file)
    tls_file_list = os.listdir(path_0 + 'tls')
    for file in tls_file_list:
        if os.path.getsize(path_0 + 'tls\\' + file) < 1024 * 10:
            os.remove(path_0 + 'tls\\' + file)
    # 去重传



    # 分文本
    # output_test_bin(path_0 + 'http')
    # 分前n个报文
    # split_by_packet()
