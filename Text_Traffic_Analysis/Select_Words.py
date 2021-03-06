import collections
import string
import numpy as np
import math
import codecs
from Text_Traffic_Analysis.Packet_Marking import *

def init_word_weight(word_set):
    # 定义词权重供筛选Top使用
    # 大部分协议关键词均处于[3, 15]范围内
    low_l = 3
    high_l = 15
    total_count = sum(w[1] for w in word_set)
    weighted_words = []
    w_values = []
    for w in word_set:
        wl = len(w[0])
        if low_l <= wl <= high_l:
            weight = math.log(1 + w[1] / total_count)
        elif wl < low_l:
            weight = math.log(1 + w[1] / total_count) * (wl / low_l)
        else:
            weight = math.log(1 + w[1] / total_count) * (high_l / wl)
        w_values.append(weight)

    w_avg = np.mean(w_values)
    w_std = np.std(w_values)

    # 对权值进行标准化操作
    for (w, v) in zip(word_set, w_values):
        if len(w[0]) == 0:
            continue
        ww = (w[0], (v - w_avg)/w_std)
        # ww = (w[0], v)
        weighted_words.append(ww)

    weighted_words.sort(key=lambda w: w[1], reverse=True)
    return weighted_words

def match_Regular_Expression(word, RegularExpression):
    Flag = 0
    for reguE in RegularExpression:
        compile_http = re.compile(reguE)
        if compile_http.match(word):
            Flag = 1
            break
        else:
            continue
    if Flag == 1:
        return True
    else:
        return False

def remove_marks(word):
    # 去除分段词集前后的符号
    word = word.strip()
    word = word.strip(string.punctuation)
    word = word.strip()
    return word

def top_words_set(seg_out_path, words_path):
    # 提取分段词集并定义权重筛选top关键词主函数
    newf = open(words_path, 'w')
    newf.close()

    def no_symbol(word):
        symbol = "!#$@%()*+,<>[\]{|}'~:`\""
        for i in symbol:
            if i in word:
                return False
            else:
                continue
        return True

    def read_pkt_seg_data(file_name):
        # 读取报文分割生成的文件，提取分段词集
        def is_version_or_ip(word):
            if '.' in word: # 包含'.'的可能是ip或版本号
                flag = 0
                if word[0] == 'v':  # version 字符串或以v开头
                    return True
                else:
                    sp = word.split('.')
                    for num in sp:
                        if num.isdigit():
                            continue
                        else:
                            flag = 1
                            break
                    if flag == 1:
                        return False
                    else:
                        return True
            else:
                return False

        SEP = '[pkt-sep]'
        f = codecs.open(file_name, 'rU', 'utf-8') #codec.open防止编码问题
        cnt = f.read()
        pkt_cnt = cnt.split(SEP)
        word_set = []
        for p in pkt_cnt:
            pkt_wset = p.split('^')
            for w in pkt_wset:
                w = remove_marks(w)
                if not w.isdigit() and 2 < len(w) < 25 and not is_version_or_ip(w):
                    if no_symbol(w):
                        word_set.append(w)
                else:
                    continue
        f.close()
        return word_set

    def word_count(words, size):
        # 统计分段词集中每个词出现的次数
        count = [['Other Words', -1]]
        count.extend(
            collections.Counter(words).most_common(size - 1))  # return the top-n most frequent words

        dictionary = dict()
        for word, _ in count:
            dictionary[word] = len(dictionary)
        data = list()
        unk_count = 0
        for word in words:
            if word in dictionary:
                index = dictionary[word]
            else:
                index = 0  # dictionary['UNK']
                unk_count += 1
            data.append(index)
        count[0][1] = unk_count
        return count, dictionary

    out_words = read_pkt_seg_data(seg_out_path)
    w_count, w_dictionary = word_count(out_words, 150)

    fh = codecs.open(words_path, 'a+')
    for w in w_count:
        fh.write("{0} --> {1}{2}".format(w[0].encode(), w[1], "\n"))
    fh.close()

    # 读http 协议关键词典
    http_dic_file = open('./Text_Traffic_Analysis/HTTP_dic', 'r')
    cnt = http_dic_file.read()
    http = cnt.split('\n')
    http_dic_file.close()
    seg = http.index('[Regular Expression:]')
    http_reguExp = http[seg + 1: len(http)]
    http_set = http[0: seg]
    init_w_count = []
    weighted_word = []
    for wc in w_count[1:]:
        if wc[0] in http_set or match_Regular_Expression(wc[0], http_reguExp):
            weighted_word.append((wc[0], 0.5))
        else:
            init_w_count.append(wc)

    weighted_word += init_word_weight(init_w_count)  # delete 'Other Words'
    tagged_weighted_word = [] # 结构：关键词，词权重，编号i
    for c, i in zip(weighted_word, range(1, len(weighted_word)+1)):
        try:
            tagged_weighted_word.append((bytes(c[0], encoding='utf-8'), c[1], i))
        except:
            tagged_weighted_word.append((bytes(c[0]), c[1], i))
    tagged_weighted_word.sort(key=lambda w: w[1], reverse=True)
    del weighted_word

    print("[info] Select top-150 words and define word's weight successfully")
    return tagged_weighted_word

def select_key_words(tagged_words, datapath, p_outpath, mode):
    # # 所有关键词集
    # print("\n[out] Final Keywords:(Token No., <Words, Weight>)")
    # print('-' * 40)
    # for w in tagged_words:
    #     print(" (No." + str(w[2]) + ":<" + str(w[0])[1:] + ", {0:.3f}>)".format(w[1]))
    # print("[info] Total ", len(tagged_words), " word tokens")

    final_words = []
    for w in tagged_words:  # 关键词筛选
        if w[1] > 0:
            final_words.append(w)

    # print("\n[out] Final Keywords:(Token No., <Words, Weight>)")
    # print('-' * 40)
    # for w in final_words:
    #     print(" (No." + str(w[2]) + ":<" + str(w[0])[1:] + ", {0:.3f}>)".format(w[1]))
    # print("[info] Total ", len(final_words), " word tokens")

    # # 人工细化特征字符串
    # print("\n[in] Delete NO Feature String from Keywords (split with ','): ")
    # select = input()
    # sel_Num = [int(x) for x in select.split(',')]
    # for w in final_words:
    #     if w[2] in sel_Num:
    #         final_words.remove(w)

    # 确定关键词前向后向，同时将流量按照前向后向分开
    forward_word = []
    backward_word = []
    forward_num, backward_num, forward_data, backward_data = word_direction(final_words, datapath, mode)
    for w in final_words:  # 存在提取的关键词在两个方向的报文中都出现的情况
        if w[2] in forward_num:
            forward_word.append(w)
        if w[2] in backward_num:
            backward_word.append(w)

    print("\n[out] Forward Flow Keywords:(Token No., <Words, Weight>)")
    print('-' * 50)
    for w in forward_word:
        print(" (No." + str(w[2]) + ":<" + str(w[0])[1:] + ", {0:.3f}>)".format(w[1]))
    print("[info] Total ", len(forward_word), " forward keywords.")

    print("\n[out] Backward Flow Keywords:(Token No., <Words, Weight>)")
    print('-' * 50)
    for w in backward_word:
        print(" (No." + str(w[2]) + ":<" + str(w[0])[1:] + ", {0:.3f}>)".format(w[1]))
    print("[info] Total ", len(backward_word), " backward keywords.")

    f_p_outpath = p_outpath + "_fw"
    print("\nForward Pattern output file path: ", f_p_outpath)
    packets_mark_with_words(f_p_outpath, forward_data, forward_word)

    b_p_outpath = p_outpath + "_bw"
    print("\nBackward Pattern output file path: ", b_p_outpath)
    packets_mark_with_words(b_p_outpath, backward_data, backward_word)

    return forward_word, backward_word, forward_data, backward_data