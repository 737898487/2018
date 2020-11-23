import dpkt
import re
import os

def packets_split(datapath, mode):
    # 将前向流和后向流分开
    print("\nStart Split Forward and Backward Packets...")
    file_name_list = os.listdir(datapath)
    FP = []
    BP = []
    FB = []
    sum_packets = 0
    for file_name in file_name_list:
        try:
            address = []
            f = open(datapath + file_name, "rb")
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                data = tcp.data
                FB.append(data) # 所有报文数据集合

                if ip.src not in address:
                    address.append(ip.src)
                if ip.dst not in address:
                    address.append(ip.dst)

                if mode == 'common': # 常规协议目的端口号小于1024，利用端口号区分前向后向
                    if tcp.dport < 1024 :
                        FP.append(data)
                    elif tcp.sport < 1024 :
                        BP.append(data)
                elif mode == 'app': # app流量采用ipsrc-->ipdst为前向、ipdst-->ipsrc为后向
                    if ip.src == address[0]:
                        FP.append(data)
                    else:
                        BP.append(data)
                sum_packets += 1
        except Exception as exc:
            print(exc)

    print("[info] Split {0}-flow {1}-packet {2}-forward packet {3}-backward packet".format(len(file_name_list), sum_packets, len(FP), len(BP)))
    print("Split Packets successfully.")
    return FP, BP, FB

def get_word_index(data, word):
    index = -1
    iters = re.finditer(word, data)
    locations = [it.start() for it in iters]
    if len(locations) != 1:
        for i in locations:
            if chr(data[i - 1]).isalpha():  # word是另一个字符串的子串
                # print("{0} location is sub".format(i))
                index = -1
            elif chr(data[i + len(word)]).isalpha():
                # print("{0} location is sub".format(i))
                index = -1
            else:
                # print("{0} location is not sub".format(i))
                index = i
                break
    else:
        index = locations[0]

    return index

def word_direction(word_set, datapath, mode):
    # 确定关键词前向后向，同时将流量按照前向后向分开
    forward = 0
    backward = 1
    num_for = []
    num_back = []
    dataset_for, dataset_back, dataset = packets_split(datapath, mode)

    for w in word_set:
        direction = []
        for data in dataset:
            if str(w[0])[2:-1].isalpha():
                index = get_word_index(data, w[0])
                if index != -1 :
                    if data in dataset_for:
                        direction.append(forward)
                    elif data in dataset_back:
                        direction.append(backward)
                else:
                    continue
            else:
                index = data.find(w[0])
                if index != -1 :
                    if data in dataset_for:
                        direction.append(forward)
                    elif data in dataset_back:
                        direction.append(backward)
                else:
                    continue
        # print("No." + str(w[2]) +" word:" + str(w[0])[1:] +" forward count:" + str(direction.count(forward)) + " backward count:" + str(direction.count(backward)))
        if direction.count(forward) == 0:
            # if direction.count(backward) / len(dataset_back) > 0.3:
                num_back.append(w[2])
        elif direction.count(backward) == 0:
            # if direction.count(forward) / len(dataset_for) > 0.3:
                num_for.append(w[2])
        else:
            if direction.count(forward)/len(dataset_for) < 0.1 and direction.count(backward) != 0: # 该关键词在前向报文集中出现次数很少
                num_back.append(w[2])
            elif direction.count(backward)/len(dataset_back) < 0.1 and direction.count(forward) != 0: # 该关键词在后向报文集中出现次数很少
                num_for.append(w[2])
            else:
                num_for.append(w[2])
                num_back.append(w[2])
    return num_for, num_back, dataset_for, dataset_back

def packets_mark_with_words(p_outpath, data_set, words):
    # 生成关键词存储文件，并使用关键词对流量报文进行标注
    fp = open(p_outpath + "_dic", 'wb')
    print("Keywords output file path:" + p_outpath + "_dic")
    for w in words:
        fp.write(str(w[2]).encode() + b'^' + w[0] + b"\n")
    fp.close()

    words.sort(key=lambda w: len(w[0]), reverse=True)

    print("Start Packets Marking...")
    fp = open(p_outpath, 'wb')
    for data in data_set:
        plen = len(data)
        if plen == 0:
            continue
        code = [0] * plen

        for x in words:
            index = data.find(x[0])
            if index == -1:
                continue
            elif code[index] == 0:
                for k in range(index, index + len(x[0])):
                    code[k] = x[2]
                index = data.find(x[0], index + len(x[0])+1)
                while index != -1:
                    if code[index] == 0:
                        for k in range(index, index + len(x[0])):
                            code[k] = x[2]
                    index = data.find(x[0], index + len(x[0]) + 1)
            elif (index == 0 or code[index] != code[index - 1]) and len(
                    set(code[index:index + len(x[0])])) > 1:
                for k in range(index, index + len(x[0])):
                    code[k] = x[2]
            else:
                for k in range(index, index + len(x[0])):
                    code[k] = x[2]
        pre_c = 0
        data_token = b''
        for c, k in zip(code, range(len(code))):
            if k == 0:
                pre_c = c
                data_token += str(c).encode()
                data_token += b","
                continue
            if pre_c == c:
                continue
            if pre_c != c:
                data_token += str(c).encode()
                data_token += b","
                pre_c = c

        data_token = data_token[:-1]
        data_token += b"\n"
        fp.write(data_token)
    fp.close()
    print("[info] {0}-packets Mark with Keywords successfully.".format(len(data_set)))
