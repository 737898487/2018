import shutil
import os
import dpkt


def remove_file(old_path, new_path):
    # print(old_path)
    # print(new_path)
    filelist = os.listdir(old_path)  # 列出该目录下的所有文件,listdir返回的文件列表是不包含路径的。
    # print(filelist)
    for file in filelist:
        if 'League of Legends.exe' not in file:
            continue
        src = os.path.join(old_path, file)
        dst = os.path.join(new_path, file)
        # print('src:', src)
        # print('dst:', dst)
        shutil.move(src, dst)


def is_full_tls(file_path):
    f = open(file_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    print("reading:", file_path)
    for (ts, buf) in pcap:
        eth = dpkt.ethernet.Ethernet(buf)  # 解包，物理层
        ip = eth.data
        app = ip.data
        if app.data.hex()[14:16] == '01':
            f.close()
            return True
        else:
            f.close()
            return False
    return False


if __name__ == "__main__":
    src = 'D:\\协议逆向\\原始zip\\新建文件夹\\test\\tcp'
    dst = 'D:\\协议逆向\\原始zip\\新建文件夹\\lol'
    folderlist = os.listdir(src)
    for file in folderlist:
        new_src = os.path.join(src, file)
        if not is_full_tls(new_src):
            print("removing:", file_path)
            os.remove(new_src)
