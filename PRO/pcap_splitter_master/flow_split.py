from pcap_splitter.splitter import PcapSplitter
import os
from pcap_splitter_master.get_pcap_time import get_pcap_time


def pcap_flow_split(app_name, path, path_0, path_2):
    '''
    按规则对pcap进行分割
    :param app_name:
    :param path: 要分割的pcap文件目录
    :param path_0: 分割后的pcap文件存放目录
    :param path_2:  pcapsplitter.exe的路径
    :return:
    '''
    ps = PcapSplitter(path, path_2 + "PcapSplitter.exe")
    if app_name == 'crossfire_mobile':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp portrange 61000-62000"))
        if not os.path.exists(path_0 + "\\udp_1"):
            os.mkdir(path_0 + "\\udp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_1", "udp"))
        return 0

    elif app_name == 'douyu_mobile':
        print('splitting ' + app_name, ps.split_by_session(path_0, "tcp port 8080"))
        return 0

    elif app_name == 'pptv_mobile':
        print('splitting ' + app_name, ps.split_by_session(path_0, "tcp port 80"))
        return 0

    elif app_name == 'hpjy':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp port 17500"))
        if not os.path.exists(path_0 + "\\udp_1"):
            os.mkdir(path_0 + "\\udp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_1", "udp"))
        if not os.path.exists(path_0 + "\\udp_2"):
            os.mkdir(path_0 + "\\udp_2")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_2", "udp"))
        return 0

    elif app_name == 'mrzh':
        print('splitting ' + app_name, ps.split_by_session(path_0, "udp portrange 12000-13000"))
        return 0

    elif app_name == 'wzry':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp portrange 30000-35000"))
        if not os.path.exists(path_0 + "\\udp_1"):
            os.mkdir(path_0 + "\\udp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_1", "udp portrange 30000-45000"))
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_1", "udp portrange 10000-22000"))
        return 0

    elif app_name == 'crossfire_pc':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp portrange 10000-11000"))
        if not os.path.exists(path_0 + "\\tcp_2"):
            os.mkdir(path_0 + "\\tcp_2")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_2", "tcp port 80"))
        if not os.path.exists(path_0 + "\\udp_1"):
            os.mkdir(path_0 + "\\udp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\udp_1", "udp  portrange 11500-14000"))
        return 0

    elif app_name == 'lol':
        print('splitting ' + app_name, ps.split_by_session(path_0, "udp"))
        return 0

    elif app_name == 'wechat_file':
        print('splitting ' + app_name, ps.split_by_session(path_0, "tcp"))
        return 0

    elif app_name == 'wechat':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        # print('splitting ' + app_name, ps.split_by_session(path_0, "tcp port 443"))
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1"))
        return 0

    elif app_name == 'wechat_mobile':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp port 8080"))
        if not os.path.exists(path_0 + "\\tcp_2"):
            os.mkdir(path_0 + "\\tcp_2")
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_2", "tcp port 443"))
        return 0

    elif app_name == 'ftp':
        if not os.path.exists(path_0 + "\\tcp_1"):
            os.mkdir(path_0 + "\\tcp_1")
        # print('splitting ' + app_name, ps.split_by_session(path_0, "tcp port 443"))
        print('splitting ' + app_name, ps.split_by_session(path_0 + "\\tcp_1", "tcp port 21"))
        return 0

    elif app_name == 'Fortnite':
        print('splitting ' + app_name, ps.split_by_session(path_0, "udp portrange 8500-9500"))
        return 0

    elif app_name == 'pubg':
        print('splitting ' + app_name, ps.split_by_session(path_0, "udp"))
        return 0

    elif app_name == 'bigo_live':
        print('splitting ' + app_name, ps.split_by_session(path_0, "tcp portrange 7000-8000"))
        return 0

    elif app_name == 'douyu_pc':
        pass
        return 0

    elif app_name == 'pptv_pc':
        print('splitting ' + app_name, ps.split_by_session(path_0, "tcp port 80"))
        return 0


if __name__ == "__main__":
    path = 'D:\\协议逆向\\原始zip\\mmtls\\'
    path_0 = 'D:\\协议逆向\\filter\\ftp'
    path_2 = 'D:\\Setups\\pcapplusplus-19.12-windows-mingw-w64-gcc-6.3.0\\examples\\'
    app_name = 'ftp'

    folderlist = os.listdir(path)
    for file in folderlist:
        pcap_flow_split(app_name,  path + file, path_0, path_2)
    filter_filelist = os.listdir(path_0)
    for file in filter_filelist:
        try:
            if get_pcap_time(path_0 + '\\' + file) < 0 or os.path.getsize(
                    path_0 + '\\' + file) < 1024 * 1:
                # 流持续时间小于50s,删除
                os.remove(path_0 + '\\' + file)
        except Exception as e:
            print(e)
            files = os.listdir(path_0  + '\\' + file)
            print(path_0  + '\\' + file)
            for tcp_udp in files:
                if get_pcap_time(path_0  + '\\' + file + '\\' + tcp_udp) < 0 or os.path.getsize(
                        path_0  + '\\' + file + '\\' + tcp_udp) < 1024 * 1:
                    # 流持续时间小于50s,删除
                    os.remove(path_0  + '\\' + file + '\\' + tcp_udp)
    '''
    filter_filelist = os.listdir(path_0 + app_name)
    for file in filter_filelist:
        try:
            if os.path.getsize(path_0 + app_name + '\\' + file) < 1024 * 257:
                os.remove(path_0 + app_name + '\\' + file)
        except Exception as e:
            files = os.listdir(path_0 + app_name + '\\' + file)
            print(path_0 + app_name + '\\' + file)
            for tcp_udp in files:
                if os.path.getsize(path_0 + app_name + '\\' + file + '\\' + tcp_udp) < 1024 * 200:
                    # 小于200KB,删除
                    os.remove(path_0 + app_name + '\\' + file + '\\' + tcp_udp)
            files = os.listdir(path_0 + app_name + '\\' + file)
            for tcp_udp in files:
                if file == 'udp_1':
                    if not 20000 < get_port(path_0 + app_name + '\\' + file + '\\' + tcp_udp)[0] < 65000:
                        os.remove(path_0 + app_name + '\\' + file + '\\' + tcp_udp)
                if file == 'udp_2':
                    if not 10000 < get_port(path_0 + app_name + '\\' + file + '\\' + tcp_udp)[0] < 12000:
                        os.remove(path_0 + app_name + '\\' + file + '\\' + tcp_udp)
    '''