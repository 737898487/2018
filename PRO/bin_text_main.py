from libs.read_pcap import read_pcap_2
from bin_text_test.bin_text import printable
from libs.split_pcap import split_by_packet
import os
import time


'''
分离一条流中的二进制和文本消息，生成2个pcap
'''

'''
老方法
def test_bin(file_path):
    pcap_dict = read_pcap_2(file_path)

    text_pkt_list = []
    bin_pkt_list = []
    contin_count = 0
    for count,payload in pcap_dict.items():
        if contin_count < 20:
            i = 0
            slice = len(payload) // 10
            if slice % 2 == 1:
                slice += 1

            success_list = []
            while (1):
                temp_list = payload[i * slice: (i + 1) * slice]
                success, r = printable(temp_list)
                success_list.append(success)
                # print("length = ", len(temp_list))
                # print("success =", success)
                # print("r = ", r)
                i += 1
                if len(temp_list) < slice:
                    break

            # if success_list[0] == True and success_list[1] == True :
            #     # 文本
            #     text_pkt_list.append(count)
            if success_list.count(True) > 3:
                text_pkt_list.append(count)
            else:
                # 二进制
                contin_count += 1
                bin_pkt_list.append(count)
        else:
            bin_pkt_list.append(count)

    return text_pkt_list,bin_pkt_list
'''

def test_bin(file_path, window_size = 6, suc_1= 0.2, suc_2 = 0.8):
    pcap_dict = read_pcap_2(file_path)

    text_pkt_list = []
    bin_pkt_list = []
    contin_count = 0
    start = time.time()
    for count,payload in pcap_dict.items():
        if contin_count < 200:
            if len(payload) > 200:
                suc_threshold_1 = 30
            else:
                suc_threshold_1 = int((len(payload) - window_size * 2) // 2 * suc_1)
            suc_threshold_2 = int((len(payload) - window_size * 2) // 2 * suc_2)
            i = 0
            success_count = 0
            while True:
                temp_list = payload[i: i + window_size * 2]
                success, r = printable(temp_list)
                if success == True:
                    success_count += 1
                i += 2
                if len(temp_list) < window_size * 2:
                    break
            # print(success_count)
            if success_count > suc_threshold_2:
                contin_count = 0
                text_pkt_list.append(count)
            elif success_count > suc_threshold_1:
                # 二进制和文本
                contin_count = 0
                text_pkt_list.append(count)
                bin_pkt_list.append(count)
            else:
                contin_count += 1
                bin_pkt_list.append(count)
        else:
            bin_pkt_list.append(count)
    end = time.time()
    print("get bin/text list time: %.2f seconds" %(end - start))
    return text_pkt_list, bin_pkt_list


def output_test_bin(file_path):
    filelist = os.listdir(file_path)
    if '.' in filelist[0] or '.' in filelist[-1]:
        if not os.path.exists(file_path + "\\text"):
            os.mkdir(file_path + "\\text")
        if not os.path.exists(file_path + "\\bin"):
            os.mkdir(file_path + "\\bin")
        j = 1
        k = 1
        for each_file in filelist:
            # print(each_file)
            try:
                text_pkt_list, bin_pkt_list = test_bin(file_path + '\\' + each_file)
                print('将', len(text_pkt_list), '个包划分为文本类')
                flag = split_by_packet(file_path + '\\' + each_file, file_path + "\\text\\", str(k) + '.pcap', text_pkt_list)
                # print('将', len(bin_pkt_list), '个包划分为二进制类')
                # split_by_packet(file_path + '\\' + each_file, file_path + "\\bin\\", str(k) + '.pcap', bin_pkt_list)
                if flag:
                    j += 1
                if (len(bin_pkt_list)) > 0:
                    k += 1
            except Exception as e:
                print(e)
    else:
        for tcp_udp_folder in filelist:
            newlist = os.listdir(file_path + '\\' + tcp_udp_folder)
            if not os.path.exists(file_path + '\\' + tcp_udp_folder + "\\text"):
                os.mkdir(file_path + '\\' + tcp_udp_folder + "\\text")
            if not os.path.exists(file_path + '\\' + tcp_udp_folder + "\\bin"):
                os.mkdir(file_path + '\\' + tcp_udp_folder + "\\bin")
            j = 1
            k = 1
            for each_file in newlist:
                # print(each_file)
                try:
                    text_pkt_list, bin_pkt_list = test_bin(file_path + '\\' + tcp_udp_folder + '\\' + each_file)
                    print('将', len(text_pkt_list), '个包划分为文本类', end = '')
                    flag = split_by_packet(file_path + '\\' + tcp_udp_folder + '\\' + each_file, file_path + '\\' + tcp_udp_folder + "\\text\\", str(j) + '.pcap',
                                    text_pkt_list)
                    # print('将', len(bin_pkt_list), '个包划分为二进制类', end = '')
                    # split_by_packet(file_path + '\\' + tcp_udp_folder + '\\' + each_file, file_path + '\\' + tcp_udp_folder + "\\bin\\", str(k) + '.pcap', bin_pkt_list)
                    if flag:
                        j += 1
                    if (len(bin_pkt_list)) > 0:
                        k += 1
                except Exception as e:
                    print(e)
    print(k)
    print(len(filelist))


if __name__ == "__main__":
    path = "D:\\协议逆向\\原始zip\\新建文件夹\\test\\tcp0"
    # path = "D:\\协议逆向\\filter\\filter_app_flow\\pptv_mobile"
    folderlist = os.listdir(path)
    # for folder in folderlist:
    output_test_bin(path)
