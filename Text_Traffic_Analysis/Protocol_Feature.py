#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import collections
import json
import dpkt
import os
import numpy as np
from Text_Traffic_Analysis.Select_Words import match_Regular_Expression, remove_marks

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

    tra.information_dispaly()

    tra.write_json()



