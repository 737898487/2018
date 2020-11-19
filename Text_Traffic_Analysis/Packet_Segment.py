import dpkt
import os

def segment_with_delimiter(data, length, seg_out, vote_file):
    url_delim = ['?', '&', '='] # url常用分界符
    common_delim = [';', ':'] # 其余常规分界符
    delimiter_set = url_delim + common_delim
    SEP = '[pkt-sep]'

    def read_vote_file(fp, votes):
        delims = ' '
        try:
            vs = fp.readline().split(delims)
        except:
            return
        i = 0
        for x in vs[:-1]:
            votes[i] = int(x)
            i += 1

    def no_delimiter(temp):
        flag = 1
        for i in range(0, len(temp)):
            if chr(temp[i]) in common_delim:
                flag = 0
                break
        if flag == 1:
            return True
        else:
            return False

    # vote by delimiter_set
    key_words_list = []
    votes = [1] * 1600
    seg_str = ''
    spcae_flag = 1
    start = 0
    end = 0
    for i in range(0, length):
        if chr(data[i]) == '(':
            start = i
            end = data.find(b')', start + 1, start + 50)
        if start <= i <= end: # 忽略括号对()内的字符串
            continue
        elif end == -1:
            votes[i] += 3
        else:
            if chr(data[i]) in delimiter_set and chr(data[i]) != ':':
                votes[i] += 3
            elif chr(data[i]) == ':' and (i+1 != length and chr(data[i+1]) == ' '): #常规协议分界符为': '(冒号+空格)
                    votes[i] += 3
            elif chr(data[i]) == ' ' and chr(data[i-1]) != ':' and spcae_flag: # 空格分界符单独处理
                j = data.find(b'\n', i+1, length)
                temp = data[i+1: j]
                if no_delimiter(temp) :
                    votes[i] += 3
                    spcae_flag = 0
            elif data[i] < 32 or data[i] > 126 : # 二进制作为分界符
                votes[i] += 3
        seg_str += "{} ".format(votes[i])
    seg_str += '\r'
    vote_file.write(seg_str)

    read_vote_file(vote_file, votes)
    seg_str = b"^"
    pre_i = 0
    for i in range(0, length):
        seg_str += str.encode(chr(data[i]))
        if votes[i] > 3: # or votes[i] == 20 :
            seg_str += b"^"
            if pre_i == 0:
                kw = data[pre_i:i + 1]
            else:
                kw = data[pre_i + 1:i + 1]
            key_words_list.append(kw)
            pre_i = i
    seg_str += str.encode(SEP)
    seg_out.write(seg_str)
    return key_words_list

def pkt_seg_by_delimiters(datapath, outpath):
# datapath pcap文件储存目录
# outpath 输出文件目录

    vote_file = open(outpath + "_vo", "w")
    vote_file.close()
    seg_out = open(outpath, "w")
    seg_out.close()
    vote_file = open(outpath + "_vo", "a")
    seg_out = open(outpath, "ab")

    words = []
    print("\nStart Packets Segment...")
    file_name_list = os.listdir(datapath)
    sum_packets = 0
    sum_byte = 0
    for file_name in file_name_list:
        try:
            f = open(datapath + file_name, "rb")
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                data = tcp.data

                sum_byte += len(data)
                data_text = b"" # 重组报文文本类数据，将不可读部分删除，并添加分界符'\n'
                for j in range(0, len(data)):
                    if 32 <= data[j] <= 126 or data[j] == 10 or data[j] == 13:
                        data_text += chr(data[j]).encode()
                        if j + 1 != len(data) and (data[j + 1] > 126 or data[j + 1] < 32):
                            data_text += b'\r'

                # 开始投票分段
                key_words_list = segment_with_delimiter(data_text, len(data_text), seg_out, vote_file)
                words += key_words_list
                sum_packets += 1
        except Exception as e:
            # print("\n[error] Segment Process break abnormally.")
            # print("Something wrong with Packet {0}, lost or error".format(file_name))
            # break
            print(e)

    print("[info] {0}-flow {1}-packet {2}-byte dealt".format(len(file_name_list), sum_packets, sum_byte))
    print("Packet Segment successfully.")

    vote_file.close()
    seg_out.close()
    return words
