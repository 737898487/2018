from libs.pcap_splitter import PcapSplitter
import os
from libs.read_pcap import read_pcap_2
from bin_text_test.bin_text import printable


def parse(src_path, dst_path, app_name, keep_only_app, remove, flow_packets):
    ps = PcapSplitter(app_name)
    filepath = os.listdir(src_path)
    for file in filepath:
        ps.split_by_session(os.path.join(src_path, file), dst_path, keep_only_app, remove, flow_packets)
    filepath = os.listdir(dst_path)

    if not os.path.exists(os.path.join(dst_path, "text_udp")):
        os.mkdir(os.path.join(dst_path, "text_udp"))
    if not os.path.exists(os.path.join(dst_path, "text_tcp")):
        os.mkdir(os.path.join(dst_path, "text_tcp"))
    if not os.path.exists(os.path.join(dst_path, "bin_udp")):
        os.mkdir(os.path.join(dst_path, "bin_udp"))
    if not os.path.exists(os.path.join(dst_path, "bin_tcp")):
        os.mkdir(os.path.join(dst_path, "bin_tcp"))

    for file in filepath:
        bin_t = 0
        text_u = 0
        bin_u = 0
        text_t = 0
        try:
            if "text_" in file or "bin_" in file:
                continue
            work_path = os.path.join(dst_path, file)
            pcap_list = os.listdir(work_path)
            pcap_dict = read_pcap_2(os.path.join(work_path, pcap_list[0]))
            for count, payload in pcap_dict.items():
                temp_list = payload[0:-1]
                success, r = printable(temp_list)
                if r > 0.9:  # text
                    if "tcp" in file:
                        os.rename(work_path, os.path.join(dst_path, "text_tcp") + "\\" + str(text_t))
                        text_t += 1
                    else:
                        os.rename(work_path, os.path.join(dst_path, "text_udp") + "\\" + str(text_u))
                        text_u += 1
                else:  # bin
                    if "tcp" in file:
                        os.rename(work_path, os.path.join(dst_path, "bin_tcp") + "\\" + str(bin_t))
                        bin_t += 1
                    else:
                        os.rename(work_path, os.path.join(dst_path, "bin_udp") + "\\" + str(bin_u))
                        bin_u += 1
                break
        except Exception as e:
            print(e)


if __name__ == "__main__":
    path_src = "D:\\协议逆向\\原始zip\\新建文件夹\\爱奇艺_安卓100-149"
    path_dst = "D:\\协议逆向\\原始zip\\新建文件夹\\test"
    parse(path_src, path_dst)
