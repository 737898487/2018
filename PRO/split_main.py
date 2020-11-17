import os
from pcap_splitter_master.flow_split import pcap_flow_split
from pcap_splitter_master.get_pcap_time import get_pcap_time


def split(path_0 = 'D:\\协议逆向\\filter\\filter_app_flow\\',
          path = 'D:\\协议逆向\\原始zip\\测试流量\\',
          path_2 = 'D:\\Setups\\pcapplusplus-19.12-windows-mingw-w64-gcc-6.3.0\\examples\\'):

    # path_0  目的文件夹
    # path  源文件夹
    # path_2 pcap++路径

    folderlist = os.listdir(path)
    # print(folderlist)


    for folder in folderlist:
        try:
            filelist = os.listdir(path + folder)
            # print(filelist)
            if 'crossfire_mobile' in folder:
                if not os.path.exists(path_0 + "crossfire_mobile"):
                    os.mkdir(path_0 + "crossfire_mobile")
                for file in filelist:
                    pcap_flow_split('crossfire_mobile', path + folder + '\\' + file, path_0 + "crossfire_mobile", path_2)
                continue
            elif 'douyu_mobile' in folder:
                if not os.path.exists(path_0 + "douyu_mobile"):
                    os.mkdir(path_0 + "douyu_mobile")
                for file in filelist:
                    pcap_flow_split('douyu_mobile', path + folder + '\\' + file, path_0 + "douyu_mobile", path_2)
                continue
            elif 'pptv_mobile' in folder:
                if not os.path.exists(path_0 + "pptv_mobile"):
                    os.mkdir(path_0 + "pptv_mobile")
                for file in filelist:
                    pcap_flow_split('pptv_mobile', path + folder + '\\' + file, path_0 + "pptv_mobile", path_2)
                continue
            elif '和平精英' in folder:
                if not os.path.exists(path_0 + "hpjy"):
                    os.mkdir(path_0 + "hpjy")
                for file in filelist:
                    pcap_flow_split('hpjy', path + folder + '\\' + file, path_0 + "hpjy", path_2)
                continue
            elif '明日之后' in folder:
                if not os.path.exists(path_0 + "mrzh"):
                    os.mkdir(path_0 + "mrzh")
                for file in filelist:
                    pcap_flow_split('mrzh', path + folder + '\\' + file, path_0 + "mrzh", path_2)
                continue
            elif '王者荣耀' in folder:
                if not os.path.exists(path_0 + "wzry"):
                    os.mkdir(path_0 + "wzry")
                for file in filelist:
                    pcap_flow_split('wzry', path + folder + '\\' + file, path_0 + "wzry", path_2)
                continue
            elif 'crossfire_pc' in folder:
                if not os.path.exists(path_0 + "crossfire_pc"):
                    os.mkdir(path_0 + "crossfire_pc")
                for file in filelist:
                    # CF规则切分pcap
                    pcap_flow_split('crossfire_pc', path + folder + '\\' + file, path_0 + "crossfire_pc", path_2)
                continue
            elif 'lol' in folder:
                if not os.path.exists(path_0 + "lol"):
                    os.mkdir(path_0 + "lol")
                for file in filelist:
                    # LOL规则切分pcap
                    pcap_flow_split('lol',  path + folder + '\\' + file, path_0 + "lol", path_2)
                continue
            elif '文件' in folder:
                if not os.path.exists(path_0 + "wechat_file"):
                    os.mkdir(path_0 + "wechat_file")
                for file in filelist:
                    # 微信文件规则切分pcap
                    pcap_flow_split('wechat_file',  path + folder + '\\' + file, path_0 + "wechat_file", path_2)
                continue
            elif '微信' in folder:
                if not os.path.exists(path_0 + "wechat"):
                    os.mkdir(path_0 + "wechat")
                for file in filelist:
                    # 微信聊天规则切分pcap
                    pcap_flow_split('wechat',  path + folder + '\\' + file, path_0 + 'wechat', path_2)
                continue
            elif '堡垒之夜' in folder:
                if not os.path.exists(path_0 + "Fortnite"):
                    os.mkdir(path_0 + "Fortnite")
                for file in filelist:
                    # 堡垒之夜规则切分pcap
                    pcap_flow_split('Fortnite',  path + folder + '\\' + file, path_0 + "Fortnite", path_2)
                continue
            elif '绝地求生' in folder:
                if not os.path.exists(path_0 + "pubg"):
                    os.mkdir(path_0 + "pubg")
                for file in filelist:
                    pcap_flow_split('pubg', path + folder + '\\' + file, path_0 + "pubg", path_2)
                continue
            elif 'bigo' in folder:
                if not os.path.exists(path_0 + "bigo_live"):
                    os.mkdir(path_0 + "bigo_live")
                for file in filelist:
                    # bigo live规则切分pcap
                    pcap_flow_split('bigo_live',  path + folder + '\\' + file, path_0 + "bigo_live", path_2)
                continue
            elif 'douyu_pc' in folder:
                if not os.path.exists(path_0 + "douyu_pc"):
                    os.mkdir(path_0 + "douyu_pc")
                for file in filelist:
                    # douyu_pc规则切分pcap
                    pcap_flow_split('douyu_pc',  path + folder + '\\' + file, path_0 + "douyu_pc", path_2)
                continue
            elif 'pptv_pc' in folder:
                if not os.path.exists(path_0 + "pptv_pc"):
                    os.mkdir(path_0 + "pptv_pc")
                for file in filelist:
                    # pptv_pc规则切分pcap
                    pcap_flow_split('pptv_pc',  path + folder + '\\' + file, path_0 + "pptv_pc", path_2)
        except NotADirectoryError as e:
            print(e)
            pass

    app_name = ["bigo_live", "crossfire_mobile", "crossfire_pc", "douyu_mobile", "douyu_pc", "Fortnite", "hpjy", "lol",
                "mrzh", "pptv_mobile", "pptv_pc", "pubg", "wechat", "wechat_file", "wzry"]
    for name in app_name:
        if name == "wechat":
            continue
        filter_filelist = os.listdir(path_0 + name)
        for file in filter_filelist:
            try:
                if os.path.getsize(path_0 + name + '\\' + file) < 1024 * 257:
                    # 小于200KB,删除
                    os.remove(path_0 + name + '\\' + file)
            except Exception as e:
                files = os.listdir(path_0 + name + '\\' + file)
                print(path_0 + name + '\\' + file)
                for tcp_udp in files:
                    if os.path.getsize(path_0 + name + '\\' + file + '\\' + tcp_udp) < 1024 * 200:
                        # 小于200KB,删除
                        os.remove(path_0 + name + '\\' + file + '\\' + tcp_udp)

    filter_filelist = os.listdir(path_0 + "wechat")
    for file in filter_filelist:
        try:
            if get_pcap_time(path_0 + "wechat" + '\\' + file) < 50 or os.path.getsize(path_0 + "wechat" + '\\' + file) < 1024 * 15:
                # 流持续时间小于50s,删除
                os.remove(path_0 + "wechat" + '\\' + file)
        except Exception as e:
            print(e)
            pass

if __name__ == "__main__":
    split()
