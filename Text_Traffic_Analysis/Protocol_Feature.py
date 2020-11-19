#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import collections
import json
import dpkt
import os
import numpy as np
from Select_Words import match_Regular_Expression, remove_marks

def find_longest_substring(s1,s2):
    m = [[0 for i in range(len(s2) + 1)] for j in range(len(s1) + 1)]  # 生成0矩阵，为方便后续计算，比字符串长度多了一列
    mmax = 0  # 最长匹配的长度
    p = 0  # 最长匹配对应在s1中的最后一位
    for i in range(len(s1)):
        for j in range(len(s2)):
            if s1[i] == s2[j]:
                m[i + 1][j + 1] = m[i][j] + 1
                if m[i + 1][j + 1] > mmax:
                    mmax = m[i + 1][j + 1]
                    p = i + 1
    return s1[p - mmax:p]  # 返回最长子串

class traffic:
    name = "" # 目标流量名称
    size = 0 # 分析目标流量pcap个数
    data_path = "" # 目标流量路径
    forward_formats = [] # 协议逆向得到的前向流量报文格式
    backward_formats = [] # 协议逆向得到的后向流量报文格式
    forward_word = [] # 解析前向协议格式得到的前向协议关键词
    backward_word = [] # 解析后向协议格式得到的后向协议关键词
    forward_data = [] # 协议前向流报文集合
    backward_data = [] # 协议后向流报文集合
    wrange = [] # 协议关键词位置范围信息
    del_word = [] # 程序运行过程中需要删除的协议关键词
    port = [] # 协议流量的常用端口
    word_seq_in_stream = [] # 将关键词按照其在流中出现先后顺序
    fix_pkt_num = {} # 保存在流中固定pkt中出现的关键词

    def __init__(self, name, fformats, bformats, fdata, bdata, path, mode):
        self.name = name
        self.forward_formats = fformats
        self.backward_formats = bformats
        self.forward_data = fdata
        self.backward_data = bdata
        self.data_path = path
        self.mode = mode
        self.flv = False

    def phrase_format_string(self):
        http_dic_file = open('HTTP_dic', 'r')
        cnt = http_dic_file.read()
        http = cnt.split('\n')
        http_dic_file.close()
        seg = http.index('[Regular Expression:]')
        http_reguExp = http[seg + 1: len(http)]
        http_set = http[0: seg]
        for f in self.forward_formats:
            word_set = f.split('-->')
            for word in word_set:
                word = word.strip()
                if '&' not in word:
                    if word == 'FLV':
                        self.flv = True
                    if word not in self.forward_word:
                        if len(word) > 3 and (not bool(re.search(r'\d', word))) and (word not in http_set and not match_Regular_Expression(word, http_reguExp)):
                            self.forward_word.append(word)
                        else:
                            if word not in self.del_word and len(word) != 0:
                                self.del_word.append(word)
                else:
                    if word not in self.del_word:
                        self.del_word.append(word)

        for f in self.backward_formats:
            word_set = f.split('-->')
            for word in word_set:
                word = word.strip()
                if '&' not in word:
                    if word == 'FLV':
                        self.flv = True
                    if word not in self.backward_word:
                        if len(word) > 3 and (not bool(re.search(r'\d', word))) and (word not in http_set and not match_Regular_Expression(word, http_reguExp)):
                            self.backward_word.append(word)
                        else:
                            if word not in self.del_word and len(word) != 0:
                                self.del_word.append(word)
                else:
                    if word not in self.del_word:
                        self.del_word.append(word)
        self.words = self.forward_word + self.backward_word

        # 处理FLV视频格式关键词
        FLV_set = ['duration', 'width', 'height', 'onMetaData', 'videodatarate',
                   'framerate', 'videocodecid', 'audiosamplerate', 'audiosamplesize', 'stereo',
                   'audiocodecid', 'audiodatarate', 'audiodelay', 'canSeekToEnd', 'creationdate',
                   'filesize', 'videokeyframe_frequency', 'audiochannels', 'audiodevice',
                   'audioinputvolume','fmleversion', 'lasttimestamp', 'presetname', 'videodevice']
        if self.flv and self.mode == 'app':
            self.words = list(set(self.words).difference(set(FLV_set)))
            self.del_word += list(set(self.backward_word).intersection(set(FLV_set)))
            self.backward_word = list(set(self.backward_word).difference(set(FLV_set)))
            self.forward_word = list(set(self.forward_word).difference(set(FLV_set)))

    def infer_key_value(self):
    # 采用关键词相对于符号的相对位置完成区分
        key = []
        value = []
        if self.mode == 'app': # 应用流量采用http请求获得数据
            for word in self.words: # 前向利用url分割符区分key和value
                for data in self.forward_data + self.backward_data:
                    i = data.find(word.encode())
                    if i != -1:
                        if chr(data[i - 1]) == '=' or (chr(data[i - 1]) == ' ' and chr(data[i - 2]) == ':'):
                            if word not in value:
                                value.append(word)
                        elif chr(data[i + len(word)]) == '=':
                            if word not in key:
                                key.append(word)
                        break
                    else:
                        continue
            # for word in self.backward_word: # 后向key后一个byte为专属为02，区分key和value
            #     for data in self.backward_data:
            #         i = data.find(word.encode())
            #         if i != -1:
            #             if data[i + len(word)] == 2:
            #                 if word not in key:
            #                     key.append(word)
            #             else:
            #                 if word not in value:
            #                     value.append(word)
            #             break
            #         else:
            #             continue

        self.forward_word = list(set(self.forward_word).difference(set(value)))
        self.backward_word = list(set(self.backward_word).difference(set(value)))
        self.del_word = list(set(self.del_word) | set(value))
        self.words = list(set(self.words).difference(set(value)))

    def infer_port(self):
        file_name_list = os.listdir(self.data_path)
        temp_sport = []
        temp_dport = []
        for file_name in file_name_list:
            try:
                f = open(self.data_path + file_name, "rb")
                pcap = dpkt.pcap.Reader(f)
                temp = []
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    if tcp.sport < 1024:
                        if tcp.dport not in temp:
                            temp.append(tcp.dport)
                        if tcp.sport not in temp:
                            temp.append(tcp.sport)
                    elif tcp.dport < 1024:
                        if tcp.sport not in temp:
                            temp.append(tcp.sport)
                        if tcp.dport not in temp:
                            temp.append(tcp.dport)
                    else:
                        if tcp.sport not in temp:
                            temp.append(tcp.sport)
                        if tcp.dport not in temp:
                            temp.append(tcp.dport)
                temp_sport.append(temp[0])
                temp_dport.append(temp[1])
            except:
                print("\n[error] Segment Process break abnormally.")
                print("Something wrong with Packet num-{0}, lost or error".format(file_name))
                break

        spco = collections.Counter(temp_sport)
        dpco = collections.Counter(temp_dport)
        port = []
        # 流量分析中，目的端口较为固定，个数相对于源端口来讲较少
        if len(spco) < len(dpco):
            for iter in spco.items():
                port.append(iter[0])
        else:
            for iter in dpco.items():
                port.append(iter[0])
        self.size = len(file_name_list)
        self.port = port

    def infer_host_agent(self):
    # 得到协议中的user-agent和host信息
        def is_ip(string):
            compile_ip = re.compile(
                '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
            if compile_ip.match(string):
                return True
            else:
                return False

        host_set = []
        user_agent_set = []
        if (80 in self.port or 8080 in self.port or 443 in self.port) and self.mode == 'app': # 基于http协议传输的app可能存在host和user-agent字段
            for data in self.forward_data:
                if b'Host:' in data:
                    i = data.find(b'Host:')
                    j = data.find(b'\r\n', i)
                    host_string = data[i:j] # Host:XXXXXXXXX
                    d = (host_string.decode()).split(": ")[1]
                    if ':' in d: # Host值为 地址:端口
                        host_set.append(d.split(':')[0])
                    else:
                        host_set.append(d)
                if b'User-Agent:' in data:
                    i = data.find(b'User-Agent:')
                    j = data.find(b'\r\n', i)
                    agent_string = data[i:j] # User-Agent:XXXXXXXXX
                    d = (agent_string.decode()).split(": ")[1]
                    if ';' in d: # User-Agent值用;区分
                        d = d.split(';')
                        for di in d:
                            di = remove_marks(di)
                            user_agent_set.append(di)
                    else:
                        user_agent_set.append(d)
        # print(collections.Counter(host_set))
        # print(collections.Counter(user_agent_set))

        counter1 = collections.Counter(host_set)
        compile_host = re.compile('\.[A-Za-z]+\.[c|n|o|e][a-z]+$')
        temp = []
        host = []
        for iter in list(counter1.keys()):
            if not is_ip(iter):  # Host 值为 ip
                 temp.append(iter)
        if len(temp) == 1:
            respan = compile_host.search(temp[0]).span()
            host.append(temp[0][respan[0]:respan[1]])
        elif len(temp) > 1:
            temp.sort(key=lambda x: len(x), reverse=True)
            i = 1
            fls = temp[0]
            while i < len(temp):
                fls = find_longest_substring(fls, temp[i])
                i += 1
            if len(fls) != 0 and fls.count('.') != 1:
                if fls.count('.') > 2:
                    respan = compile_host.search(fls).span()
                    host.append(fls[respan[0]:respan[1]])
                else:
                    host.append(fls)
            else: # host字段无公共子串；fls只包含一个'.':那么提取出来的只可能是'.com','.cn'等顶级域名
                for hostt in temp:
                    respan = compile_host.search(hostt).span()
                    host.append(hostt[respan[0]:respan[1]])
        if len(host) != 0:
            self.host = list(set(host))

        user_agent_dic_file = open('User_Agent_dic', 'r')
        cnt = user_agent_dic_file.read()
        ua_reguExp = cnt.split('\n')
        user_agent_dic_file.close()
        user_agent = []
        counter2 = collections.Counter(user_agent_set)
        for iter in list(counter2.keys()):
            if len(iter) > 0 and not bool(re.search(r'\d{2,}', iter)):
                if not match_Regular_Expression(iter, ua_reguExp) and counter2[iter]/self.size > 0.9:
                    user_agent.append(iter)
        if len(user_agent) != 0:
            self.user_agent = list(set(user_agent))

    def remove_delword_from_formats(self):
        new_formats = []
        self.del_word.sort(key=lambda w: len(w), reverse=True)
        for f in self.forward_formats:
            i = 0
            nf = f
            while i < len(self.del_word):
                st = self.del_word[i] + "-->"
                nf = nf.replace(st, '')
                i += 1
            if nf not in new_formats and nf != '\n':
                new_formats.append(nf)
        self.forward_formats = new_formats

        new_formats = []
        for f in self.backward_formats:
            i = 0
            nf = f
            while i < len(self.del_word):
                st = self.del_word[i] + "-->"
                nf = nf.replace(st, '')
                i += 1
            if nf not in new_formats and nf != '\n':
                new_formats.append(nf)
        self.backward_formats = new_formats

    # def get_pkt_num(self):
    #     file_name_list = os.listdir(self.data_path)
    #     all_loc = {}
    #     for file_name in file_name_list:
    #         try:
    #             f = open(self.data_path + file_name, "rb")
    #             pcap = dpkt.pcap.Reader(f)
    #             j = 1
    #             for ts, buf in pcap:
    #                 eth = dpkt.ethernet.Ethernet(buf)
    #                 ip = eth.data
    #                 tcp = ip.data
    #                 data = tcp.data
    #                 if data in self.forward_data:
    #                     for w in self.forward_word:
    #                         if w not in all_loc.keys():
    #                             all_loc[w] = []
    #                         if data.find(w.encode()) != -1:
    #                             all_loc[w].append(j)  # 关键词在每一条流中的位置
    #                 else:
    #                     for w in self.backward_word:
    #                         if w not in all_loc.keys():
    #                             all_loc[w] = []
    #                         if data.find(w.encode()) != -1:
    #                             all_loc[w].append(j)  # 关键词在每一条流中的位置
    #                 j += 1
    #         except:
    #             print("\n[error] Segment Process break abnormally.")
    #             print("Something wrong with Packet {0}, lost or error".format(file_name))
    #             break
    #
    #     # total = 0
    #     # for word in word_fre.keys():
    #     #     total += word_fre[word]
    #     #
    #     # for word in word_fre.keys():
    #     #     word_fre[word] = word_fre[word] / total
    #
    #     # fix_key = {}
    #     # word_in_stream = []
    #     # for key, value in all_loc.items():
    #     #     temp_coll = collections.Counter(value).most_common(1)[0][0]  # 取最高频关键词在流中位置，来确定关键词在流中的出现顺序
    #     #     if len(collections.Counter(value)) == 1:
    #     #         fix_key[key] = temp_coll
    #     #     word_in_stream.append((temp_coll, key))
    #     # word_in_stream.sort(key= lambda x:x[0], reverse= False)
    #     #
    #     # self.word_seq_in_stream = word_in_stream
    #     # self.fix_pkt_num = fix_key
    #
    #     pkt_num_contain_word = {}
    #     for key, value in all_loc.items():
    #         location = list(collections.Counter(value).keys())
    #         if len(location) == 1:
    #             if location[0] not in pkt_num_contain_word.keys():
    #                 pkt_num_contain_word[location[0]] = []
    #             pkt_num_contain_word[location[0]].append(key)
    #         else:
    #             for loci in location:
    #                 if loci not in pkt_num_contain_word.keys():
    #                     pkt_num_contain_word[loci] = []
    #                 pkt_num_contain_word[loci].append(key)
    #     print(pkt_num_contain_word)

    def get_word_set_from_formats(self):
        feature_dic = {}
        if len(self.forward_formats) == 1:
            num = len(feature_dic)+1
            feature_dic[num] = []
            ffword = self.forward_formats[0].split('-->')[0:-1]
            if len(ffword) > 6:
                feature_dic[num] = ffword[0:6]
            else:
                feature_dic[num] = ffword
        else:
            temp_ff = []
            for ff in self.forward_formats:
                num = ff.split('-->')[0:-1]
                if len(num) > 5:
                    temp_ff.append(ff)
            temp_ff.sort(key = lambda x :len(x), reverse=True)
            if len(temp_ff) > 0:
                j = 1
                fls = temp_ff[0]
                while j < len(temp_ff):
                    fls = find_longest_substring(fls, temp_ff[j])
                    j += 1

                flsword = fls.split('-->')
                word_fls = [fw for fw in flsword if len(fw) != 0 and fw != '\n']

                if len(word_fls) > 6: # 存在公共子串且公共关键词个数大于6
                    num = len(feature_dic) + 1
                    feature_dic[num] = word_fls[0:6]
                elif len(word_fls) < 3: # 存在公共关键词且关键词个数小于3，对每一种格式进行操作
                    for ff in temp_ff:
                        num = len(feature_dic) + 1
                        feature_dic[num] = []
                        ffword = ff.split('-->')[0:-1]
                        if len(ffword) > 6:
                            feature_dic[num] = ffword[0:6]
                        else:
                            feature_dic[num] = ffword
                else:
                    num = len(feature_dic) + 1
                    feature_dic[num] = word_fls

        if len(self.backward_formats) == 1:
            num = len(feature_dic) + 1
            feature_dic[num] = []
            bfword = self.backward_formats[0].split('-->')[0:-1]
            if len(bfword) > 6:
                feature_dic[num] = bfword[0:6]
            else:
                feature_dic[num] = bfword
        else:
            temp_bf = []
            for bf in self.backward_formats:
                num = bf.split('-->')[0:-1]
                if len(num) > 6:
                    temp_bf.append(bf)
            temp_bf.sort(key=lambda x: len(x), reverse=True)
            if len(temp_bf) > 0:
                j = 1
                fls = temp_bf[0]
                while j < len(temp_bf):
                    fls = find_longest_substring(fls, temp_bf[j])
                    j += 1
                # print(fls)
                flsword = fls.split('-->')
                word_fls = [bw for bw in flsword if len(bw) != 0 and bw != '\n']

                if len(word_fls) > 6:
                    num = len(feature_dic) + 1
                    feature_dic[num] = word_fls[0:6]
                elif len(word_fls) < 3: # 存在公共关键词且关键词个数小于3，对每一种格式进行操作
                    for bf in temp_bf:
                        num = len(feature_dic) + 1
                        feature_dic[num] = []
                        bfword = bf.split('-->')[0:-1]
                        if len(bfword) > 6:
                            feature_dic[num] = bfword[0:6]
                        else:
                            feature_dic[num] = bfword
                else:
                    num = len(feature_dic) + 1
                    feature_dic[num] = word_fls

        use_set = []
        for key, value in feature_dic.items():
            use_set += value
        use_set = list(set(use_set))

        under_line_word = []
        for word in list(set(self.forward_word)-set(use_set)):
            if '_'in word:
                under_line_word.append(word)
        if len(under_line_word) > 6:
            num = len(feature_dic) + 1
            feature_dic[num] = under_line_word[0:6]
        elif len(under_line_word) > 3:
            num = len(feature_dic) + 1
            feature_dic[num] = under_line_word

        under_line_word = []
        for word in list(set(self.backward_word)-set(use_set)):
            if '_'in word:
                under_line_word.append(word)
        if len(under_line_word) > 6:
            num = len(feature_dic) + 1
            feature_dic[num] = under_line_word[0:6]
        elif len(under_line_word) > 3:
            num = len(feature_dic) + 1
            feature_dic[num] = under_line_word

        if self.flv:
            FLV = ['onMetaData', 'duration', 'framerate', 'stereo', 'audiocodecid', 'videocodecid']
            num = len(feature_dic) + 1
            feature_dic[num] = FLV

        self.feature_dic = feature_dic

    # def infer_key_location(self):
    # # 得到关键在报文中的位置信息，位置范围
    #     def find_location(word, data_set):
    #     # 得到每一个关键词在数据负载中的位置范围
    #         word_range = []
    #         temp_loc = []
    #         for data in data_set:
    #             i = data.find(word.encode())
    #             if i != -1:
    #                 temp_loc.append(i/len(data))
    #
    #         temp_count = collections.Counter(temp_loc)
    #         if len(temp_count) == 1:
    #             # 关键词在报文中的位置固定，找出固定偏移量
    #             for key in temp_count.keys():
    #                 for data in data_set:
    #                     if word.encode() in data:
    #                         word_range.append(key * len(data))
    #                         break
    #         else:
    #             # 关键词在报文中的位置不固定，取高频五个位置计算
    #             most5 = temp_count.most_common(5)
    #             locations = []
    #             for key in most5:
    #                 locations.append(key[0])
    #
    #             # 采用箱型图的方式去除异常值，确定关键词在报文中的相对范围
    #             percentile = np.percentile(locations, (25, 50, 75), interpolation='linear')
    #             Q1 = percentile[0]  # 上四分位数
    #             Q3 = percentile[2]  # 下四分位数
    #             IQR = Q3 - Q1  # 四分位距
    #             ulim = Q3 + 1.5 * IQR  # 上限 非异常范围内的最大值
    #             llim = Q1 - 1.5 * IQR  # 下限 非异常范围内的最小值
    #             error = [] # 存储异常值
    #             for i in locations:
    #                 if i > ulim or i < llim:
    #                     error.append(i)
    #             locations = list(set(locations).difference(set(error)))
    #
    #             # 将关键词的范围规格化到报文的20个分段之一
    #             word_range.append(int(min(locations)*100 / 5)*5/100) # 下范围
    #             word_range.append(int(max(locations)*100 / 5 + 1)*5/100) # 上范围
    #         return (word, word_range)
    #
    #     dup = list(set(self.forward_word).intersection(set(self.backward_word)))
    #     for word in self.words:
    #         if word in dup:
    #             ran = [word, ['double']]
    #             if ran not in self.wrange:
    #                 self.wrange.append(ran)
    #         elif word in self.forward_word:
    #             ran = find_location(word, self.forward_data)
    #             self.wrange.append(ran)
    #         elif word in self.backward_word:
    #             ran = find_location(word, self.backward_data)
    #             self.wrange.append(ran)
    #
    #     # 如果关键词范围不固定，按照其范围跨度进行排序
    #     temp = []
    #     for w in self.wrange:
    #         if len(w[1]) != 1:
    #             temp.append(w)
    #     temp.sort(key= lambda x:(x[1][1]-x[1][0]), reverse= False)
    #
    #     # 固定位置关键词优先级高
    #     word_range = []
    #     for w in self.wrange:
    #         if len(w[1]) == 1 and w[1][0] != 'double':
    #             word_range.append(w)
    #     # 不固定位置关键词优先级中等
    #     word_range += temp
    #     # 双向位置关键词优先级最低
    #     for w in self.wrange:
    #         if len(w[1]) == 1 and w[1][0] == 'double':
    #             word_range.append(w)
    #
    #     self.wrange = word_range
    #
    # def word_location_in_stream(self):
    #     # 确定关键词出现在一条流的哪个报文之中
    #     def pkt_direction(value):
    #         temp = {}
    #         temp[0] = []
    #         temp[1] = []
    #         dup = list(set(self.forward_word).intersection(set(self.backward_word)))
    #         for w in value:
    #             if w not in dup:
    #                 if w in self.forward_word:
    #                     temp[0].append(w)
    #                 elif w in self.backward_word:
    #                     temp[1].append(w)
    #         if len(temp[0]) == 0:
    #             return "S2C"
    #
    #         if len(temp[1]) == 0:
    #             return "C2S"
    #
    #     i = 1
    #     all_loc = {}
    #     while i:
    #         try:
    #             f = open(self.data_path + str(i) + ".pcap", "rb")
    #             pcap = dpkt.pcap.Reader(f)
    #             j = 1
    #             for ts, buf in pcap:
    #                 eth = dpkt.ethernet.Ethernet(buf)
    #                 ip = eth.data
    #                 tcp = ip.data
    #                 data = tcp.data
    #                 if data in self.forward_data:
    #                     for w in self.forward_word:
    #                         if w not in all_loc.keys():
    #                             all_loc[w] = []
    #                         if data.find(w.encode()) != -1:
    #                             all_loc[w].append(j)  # 关键词在每一条流中的位置
    #                 else:
    #                     for w in self.backward_word:
    #                         if w not in all_loc.keys():
    #                             all_loc[w] = []
    #                         if data.find(w.encode()) != -1:
    #                             all_loc[w].append(j)  # 关键词在每一条流中的位置
    #                 j += 1
    #         except:
    #             print("\n[error] Segment Process break abnormally.")
    #             print("Something wrong with Packet num-{0}, lost or error".format(i))
    #             break
    #
    #         i += 1
    #         if i > self.size:
    #             break
    #     fix_key = {}
    #     word_in_stream = []
    #     for key, value in all_loc.items():
    #         temp_coll = collections.Counter(value).most_common(1)[0][0]  # 取最高频关键词在流中位置，来确定关键词在流中的出现顺序
    #         if len(collections.Counter(value)) == 1:
    #             fix_key[key] = temp_coll
    #         word_in_stream.append((temp_coll, key))
    #     word_in_stream.sort(key= lambda x:x[0], reverse= False)
    #
    #     self.word_seq_in_stream = word_in_stream
    #     self.fix_pkt_num = fix_key
    #
    #     pkt_num_contain_word = {}
    #     for key, value in all_loc.items():
    #         location = list(collections.Counter(value).keys())
    #         print(location)
    #         if len(location) == 1:
    #             if location[0] not in pkt_num_contain_word.keys():
    #                 pkt_num_contain_word[location[0]] = []
    #             pkt_num_contain_word[location[0]].append(key)
    #         else:
    #             for loci in location:
    #                 if loci not in pkt_num_contain_word.keys():
    #                     pkt_num_contain_word[loci] = []
    #                 pkt_num_contain_word[loci].append(key)
    #
    #     print(pkt_num_contain_word)
    #
    # def select_same_range_word(self):
    #     def get_longest_word(word_list):
    #         temp = []
    #         maxl = 0
    #         for w in word_list:
    #             if len(w) > maxl:
    #                 maxl = len(w)
    #             else:
    #                 continue
    #         for w in word_list:
    #             if len(w) == maxl:
    #                 temp.append(w)
    #         return temp[0:1]
    #
    #     def select_del_word(word_fre, value):
    #         wo = []
    #         freq = []
    #         for w in value:
    #             freq.append(word_fre[w])
    #
    #         co = collections.Counter(freq)
    #         if len(co) == 1:  # 字符串频率一样，取最长的字符串保留
    #             wo = get_longest_word(value)
    #         else:  # 频率不一样，去最高频的字符串保留
    #             m = max(freq)
    #             temp = []
    #             for k, v in word_fre.items():
    #                 if v != m:
    #                     temp.append(k)
    #             if len(temp) != 1:  # 高频且高频对应多个字符串，取长度最长的字符串保留
    #                 wo = get_longest_word(temp)
    #
    #         return list(set(value).difference(set(wo)))
    #
    #     data_set = self.forward_data + self.backward_data
    #     dup = list(set(self.forward_word).intersection(set(self.backward_word)))
    #
    #     word_fre = {}  # 关键词频数
    #     for word in self.words:
    #         if word not in word_fre:
    #             word_fre[word] = 0
    #
    #     for data in data_set:
    #         for word in word_fre.keys():
    #             if word in dup:
    #                 word_fre[word] = 0
    #             else:
    #                 iters = re.findall(word.encode(), data)
    #                 if len(iters) != 0:
    #                     word_fre[word] += len(iters)
    #     total = 0
    #     for word in word_fre.keys():
    #         total += word_fre[word]
    #
    #     for word in word_fre.keys():
    #         word_fre[word] = word_fre[word] / total
    #
    #     fw = {}
    #     bw = {}
    #     # 统计同一范围内字符串集合，将范围作为键值，在这个范围内字符串集合作为值
    #     for wr in self.wrange:
    #         if wr[0] in self.forward_word:
    #             if len(wr[1]) != 1:
    #                 if tuple(wr[1]) not in fw.keys():
    #                     fw[tuple(wr[1])] = []
    #                     fw[tuple(wr[1])].append(wr[0])
    #                 else:
    #                     fw[tuple(wr[1])].append(wr[0])
    #         if wr[0] in self.backward_word:
    #             if len(wr[1]) != 1:
    #                 if tuple(wr[1]) not in bw.keys():
    #                     bw[tuple(wr[1])] = []
    #                     bw[tuple(wr[1])].append(wr[0])
    #                 else:
    #                     bw[tuple(wr[1])].append(wr[0])
    #     # 对同一范围中的字符串进行筛选，选择删除某个字符串
    #     del_word = []
    #     for key, value in fw.items():
    #         if len(value) != 1:
    #             del_word += select_del_word(word_fre, value)
    #     for key, value in bw.items():
    #         if len(value) != 1:
    #             del_word += select_del_word(word_fre, value)
    #
    #     for dw in del_word:
    #         for wr in self.wrange:
    #             if wr[0] == dw:
    #                 self.wrange.remove(wr)
    #                 break
    #     del del_word
    #
    # def right_the_seq(self):
    #
    #     def get_from_wrang(word):
    #         for wr in self.wrange:
    #             if wr[0] == word:
    #                 return wr
    #
    #     word_range = []
    #     word_seq = {}
    #     for ws in self.word_seq_in_stream:
    #         if ws[0] not in word_seq.keys():
    #             word_seq[ws[0]] = []
    #         word_seq[ws[0]].append(ws[1])
    #
    #     if len(word_seq) == len(self.word_seq_in_stream):
    #         for key, value in word_seq.items():
    #             if get_from_wrang(value[0]) != None:
    #                 word_range.append(get_from_wrang(value[0]))
    #     else:
    #         for key, value in word_seq.items():
    #             temp_wr = []
    #             for w in value:
    #                 if get_from_wrang(w) != None:
    #                     temp_wr.append(get_from_wrang(w))
    #             # 固定位置字符串优先级最高
    #             # 将范围跨度（位置稳定性）作为键值，在这个范围内字符串集合作为值
    #             temp_dict = {}
    #             for wr in temp_wr:
    #                 if len(wr[1]) != 1:
    #                     n = round((wr[1][1] - wr[1][0]), 2)
    #                     if n not in temp_dict.keys():
    #                         temp_dict[n] = []
    #                         temp_dict[n].append(wr)
    #                     else:
    #                         temp_dict[n].append(wr)
    #                 elif wr[1][0] != 'double':
    #                     word_range.append(wr)
    #             # 按照位置范围跨度（稳定性）进行排序，较为稳定的优先级高
    #             for key, value in temp_dict.items():
    #                 value.sort(key=lambda x: x[1][0], reverse=False)
    #                 for v in value:
    #                     word_range.append(v)
    #         # 字符串双向出现的优先级最低
    #         for wr in self.wrange:
    #             if wr[1][0] == 'double':
    #                 word_range.append(wr)
    #
    #     self.wrange = word_range

    def information_dispaly(self):
        if self.mode == 'common':
            print("\n[info] Protocol name:" + self.name)
        else:
            print("\n[info] APP name:" + self.name)
        print("[info] Traffic in file folder:" + self.data_path + " Flow size:" + str(self.size))
        print("[info] Protocol Ports: ", end='')
        for p in self.port:
            print(str(p) + " ", end='')

        print("\n[info] Forward formats list:")
        for f in self.forward_formats:
            if len(f) != 0:
                print(f)

        print("\n[info] Backward formats list:")
        for f in self.backward_formats:
            if len(f) != 0:
                print(f)

        if hasattr(self, 'host'):
            print("\n[info] Host: Protocol Feature String: ", end='')
            for ht in self.host:
                print(ht + " ", end='')

        if hasattr(self, 'user_agent'):
            print("\n[info] User_agent: Protocol Feature String: ", end='')
            for ua in self.user_agent:
                print(ua + " ", end='')

        if self.mode == 'app':
            print("\n[info] FLV: " + str(self.flv))

        print("\n[info] Forward words list:")
        print(self.forward_word)

        print("\n[info] Backward words list:")
        print(self.backward_word)

        print("\n[info] Feature word set:")
        for key, value in self.feature_dic.items():
            print(str(key) + ' ', end='')
            print(value)
        # print("\n[info] Word's property: ")
        # for word_range in self.wrange:
        #     if len(word_range[1]) == 1:
        #         if word_range[1][0] != 'double':
        #             print(word_range[0] + '\'s location: ', end='')
        #             print(round(word_range[1][0], 2), end='')
        #     else:
        #         print(word_range[0] + '\'s range: ', end='')
        #         print(word_range[1], end='')
        #     if word_range[0] in self.forward_word and word_range[1][0] != 'double':
        #         print(" direction: C2S.")
        #     elif word_range[0] in self.backward_word and word_range[1][0] != 'double':
        #         print(" direction: S2C.")
        #     else:
        #         print(word_range[0] + " appear in double direction packets.")

    def write_json(self):
        json_name = ''
        tra_pro = {}
        if hasattr(self, 'name'):
            json_name = "./result/" + self.name + ".json"
            tra_pro['name'] = self.name

        if hasattr(self, 'port'):
            if len(self.port) == 1:
                tra_pro["tcp_port"] = self.port[0]
            else:
                tra_pro["tcp_port"] = self.port

        if hasattr(self, 'flv'):
            if self.mode == 'app':
                tra_pro['flv'] = str(self.flv)

        if hasattr(self, 'host'):
            if len(self.host) == 1:
                tra_pro['Host'] = self.host[0]
            else:
                tra_pro['Host'] = self.host

        if hasattr(self, 'user_agent'):
            if len(self.user_agent) == 1:
                tra_pro['User_Agent'] = self.user_agent[0]
            else:
                tra_pro['User_Agent'] = self.user_agent

        if hasattr(self, 'feature_dic'):
            for key, value in self.feature_dic.items():
                tra_pro[key] = value
        # if hasattr(self, 'wrange'):
        #     # wrange 参数[key_string, [word_range]]
        #     # [word_range]可能是区间、'double'或固定'offset'
        #     i = 1 # Feature Number
        #     for w in self.wrange:
        #         tra_pro[i] = {} # 特征字符串集合
        #         if w[0] in self.forward_word:
        #             tra_pro[i]['content'] = w[0] # 字符串内容
        #             if w[0] in self.fix_pkt_num.keys(): # 判断字符串是否在流的固定pcap中出现
        #                 tra_pro[i]['pkt_num'] = self.fix_pkt_num[w[0]]
        #             if len(w[1]) == 1: # 关键词位置信息是'double'或固定'offset'
        #                 if w[1][0] == "double":
        #                     tra_pro[i]['direction'] = w[1][0]
        #                 else:
        #                     tra_pro[i]['offset'] = round(w[1][0], 2)
        #                     tra_pro[i]['direction'] = 'C2S'
        #             else: # 关键词位置信息是区间
        #                 tra_pro[i]['location'] = "random"
        #                 # tra_pro[i]['range_low'] = w[1][0]
        #                 # tra_pro[i]['range_high'] = w[1][1]
        #                 tra_pro[i]['direction'] = 'C2S'
        #         if w[0] in self.backward_word:
        #             tra_pro[i]['content'] = w[0]
        #             if w[0] in self.fix_pkt_num.keys():
        #                 tra_pro[i]['pkt_num'] = self.fix_pkt_num[w[0]]
        #             if len(w[1]) == 1:
        #                 if w[1][0] == "double":
        #                     tra_pro[i]['direction'] = w[1][0]
        #                 else:
        #                     tra_pro[i]['offset'] = round(w[1][0], 2)
        #                     tra_pro[i]['direction'] = 'S2C'
        #             else:
        #                 tra_pro[i]['location'] = "random"
        #                 # tra_pro[i]['range_low'] = w[1][0]
        #                 # tra_pro[i]['range_high'] = w[1][1]
        #                 tra_pro[i]['direction'] = 'S2C'
        #         i += 1

        with open(json_name, 'w', encoding="utf-8") as f:
            json.dump(tra_pro, f, indent=2)

        print("\n[info] The feature string is writed successfully.")
        print("[info] Result Path: " + json_name)

def get_traffic_feature(name, forward_formats, backward_formats, forward_data, backward_data, path, mode):

    print("\nStart get feature form formats...")

    tra = traffic(name, forward_formats, backward_formats, forward_data, backward_data, path, mode)

    tra.phrase_format_string()

    tra.infer_key_value()

    tra.remove_delword_from_formats()

    tra.infer_port()

    tra.infer_host_agent()

    tra.get_word_set_from_formats()

    # tra.infer_key_location()
    #
    # if tra.mode == 'app':
    #     tra.select_same_range_word()
    #
    # tra.word_location_in_stream()
    #
    # tra.right_the_seq()

    tra.information_dispaly()

    tra.write_json()



