#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Needleman_Wunsch import Needleman_Wunsch_Merge

def read_word_dic_file(path):
    # 读取写入关键词集合的文件
    word_set = []
    f = open(path, 'r')
    cnt = f.read()
    pkt_cnt = cnt.split("\n")
    for p in pkt_cnt:
        element = p.split('^')
        if len(element) <= 1:
            continue
        word_set.append((int(element[0]),element[1]))
    return word_set

def read_token_file(p_outpath):
    # 读取关键词标注后的流量报文序列
    word_dic_path = p_outpath + "_dic"
    word_set = read_word_dic_file(word_dic_path)
    sentence_list = []
    wset_num = []
    f = open(p_outpath, 'r')
    cnt = f.read()
    pkt_cnt = cnt.split("\n")
    for p in pkt_cnt:
        pkt_wset = p.split(',')
        if len(pkt_wset) <= 1: # 去除无意义报文格式
            continue
        sentence_list.append(list(map(int, pkt_wset)))
        for w in pkt_wset:
            if int(w) not in wset_num:
                wset_num.append(int(w))
    f.close()
    if 0 in wset_num:
        wset_num.remove(0)
    return sentence_list, wset_num, word_set

# def PMI(word, frequency, sentence_list, Size):
#     # 计算关键词间PMI相似度（互信息）
#     # word_PMI = [0] * len(word) * len(word)
#     # for i in range(len(word)):
#     #     for j in range(i + 1, len(word)):
#     #         num = 0
#     #         for sentence in sentence_list:
#     #             if word[i] in sentence and word[j] in sentence:
#     #                 num += 1
#     #             Pij = num /Size
#     #             Pw0 = frequency[word[i]] / Size
#     #             Pw1 = frequency[word[j]] / Size
#     #             PMI = math.log(Pij / (Pw0 * Pw1))
#     #             word_PMI[i * len(word) + j] = PMI
#     #             word_PMI[j * len(word) + i] = PMI
#
#     word_combin = []
#     word_PMI = {}
#     i = 0
#     while i < len(word):
#         j = i
#         while j < len(word):
#             word_combin.append((word[i],word[j]))
#             j += 1
#         i += 1
#     # print(word_combin)
#     word_combin.append((0,0))
#     for w in word:
#         word_combin.append((0,w))
#     for combin in word_combin:
#         num = 0
#         for sentence in sentence_list:
#             if combin[0] in sentence and combin[1] in sentence:
#                 num += 1
#         Pcombin = num / Size
#
#         if Pcombin == 0 or combin[0] == 0:
#             word_PMI[combin] = 0
#         elif combin[0] == combin[1]:
#             word_PMI[combin] = 1
#         else:
#             # print (Pcombin,Pw0,Pw1)
#             # print(Pcombin / (Pw0 * Pw1))
#             Pw0 = frequency[combin[0]] / Size
#             Pw1 = frequency[combin[1]] / Size
#             PMI = math.log((Pcombin / (Pw0 * Pw1)), 2)
#             word_PMI[combin] = PMI
#
#     return word_PMI

# def word_location(word_num, data_sentence):
#     # 计算关键词在报文中的相对位置
#     location = []
#     for w in word_num:
#         single_word_location = []
#         for data in data_sentence:
#             if w in data :
#                 single_word_location.append(data.index(w))
#
#         loc = collections.Counter(single_word_location).most_common(1)
#         location.append([w, loc[0][0]])
#     location.sort(key=lambda x: x[1], reverse=False)
#     # for w in location:
#     #     print("Keyword {0}'s location is {1}".format(str(w[0])[2:-1], w[1]))
#     return location

def lcs_substring(s1, s2):
    # 计算两个词的最长公共子序列
    m = [[0 for i in range(len(s2) + 1)] for j in range(len(s1) + 1)]
    mmax = 0
    for i in range(len(s1)):
        for j in range(len(s2)):
            if s1[i] == s2[j]:
                m[i + 1][j + 1] = m[i][j] + 1
                if m[i + 1][j + 1] > mmax:
                    mmax = m[i + 1][j + 1]
    return mmax

def format_info(sentence_list):
    # 统计协议格式信息
    sentence_slim = dict()
    for sen in sentence_list:
        t = tuple(sen)
        try:
            sentence_slim[t] += 1
        except:
            sentence_slim[t] = 1
    # print(sentence_slim)
    sorted_sentence = list(sentence_slim.items())
    sorted_sentence.sort(key=lambda x: x[1], reverse=True)
    print("[info] Total {} sentence".format(sum([x[1] for x in sorted_sentence])))
    print("[info] Total {} different formats".format(len(sorted_sentence)))
    main_format = []
    temp = 0
    for sen, num in sorted_sentence:
        temp += num
        if temp / len(sentence_list) > 0.8:  # 筛选高频且覆盖报文数超过样本集80%的协议格式集合
            main_format.append(list(sen))
            # print("packet format:{0} --> frequency: {1}".format(sen, num))
            break
        else:
            main_format.append(list(sen))
            # print("packet format:{0} --> frequency: {1}".format(sen, num))
            continue

    record = []
    for i in range(len(main_format)):
        if i == len(main_format):
            break
        for j in range(i + 1, len(main_format)):
            mstr = lcs_substring(main_format[i], main_format[j])
            if mstr == len(main_format[i]):  # 如果某种格式是另一种格式的子格式
                if main_format[i] not in record:
                    record.append(main_format[i])
            elif mstr == len(main_format[j]):
                if main_format[j] not in record:
                    record.append(main_format[j])

    if len(record) != 0:
        for r in record:
            main_format.remove(r)

    # 对格式进行预处理
    for f in main_format:
        while 0 in f:
            f.remove(0)

    return main_format

def extract_main_format(format_set, word_set):
    # 提取主要的协议格式
    def merge_formats(formats):
        # 合并协议格式集合
        can_merged_format = []
        sim_value = []
        for i in range(len(formats)):
            if i == len(formats):
                break
            for j in range(i + 1, len(formats)):
                p1 = formats[i]
                p2 = formats[j]
                sim, p3 = Needleman_Wunsch_Merge(p1, p2) # 计算任意两种格式间相似度
                if sim > 0.8: # 相似度满足一定阈值，可以合并
                    can_merged_format.append([i, j, p3, sim])
                    sim_value.append(sim)

        merged_format = []
        if len(can_merged_format) != 0:
            flag = [0] * len(formats)  # 判断某一格式是否已经合并
            sim_loc = [v for v in sim_value]
            while len(sim_value) > 0:
                n = max(sim_value) # 筛选相似度最大的两个格式进行合并，并将合并后的格式加入格式集合
                cmf = can_merged_format[sim_loc.index(n)]
                if flag[cmf[0]] == 0 and flag[cmf[1]] == 0:
                    flag[cmf[0]] = 1
                    flag[cmf[1]] = 1
                    if cmf[2] not in merged_format:
                        merged_format.append(cmf[2])
                sim_value.remove(n)

            # 将没有合并到的格式加入最终集合
            j = 0
            for i in flag:
                if i != 1:
                    merged_format.append(formats[j])
                j += 1
        else:
            merged_format = formats
        return merged_format

    def keyword_sequence(num_seq, word_set):
        # 将推断的格式翻译成由关键词组成的句子
        sequence = ''
        i = 0
        for n in num_seq:
            if type(n) is list:
                for ni in n:
                    for w in word_set:
                        if w[0] == ni:
                            sequence += w[1]
                            if ni != n[-1]:
                                sequence += " & "
            else:
                for w in word_set:
                    if w[0] == n:
                        sequence += w[1]
            i += 1
            if i != len(num_seq):
                sequence += "-->"
            else:
                sequence += '-->\n'
        return sequence

    format_string_set =[]
    if len(format_set) == 1: # 如果只有剩一种格式，直接翻译
        format_string = keyword_sequence(format_set[0], word_set)
        format_string_set.append(format_string)
        # print(format_string)
    else: # 存在多种格式，对格式进行合并
        formats = merge_formats(format_set)
        for f in formats:
            format_string = keyword_sequence(f, word_set)
            format_string_set.append(format_string)
    return format_string_set

def infer_protocol_format(p_outpath):
    # 推断协议格式主函数
    print("\nStart infer protocol format...")
    f_p_outpath = p_outpath + "_fw"
    b_p_outpath = p_outpath + "_bw"
    f_sentence_list, f_word_num, f_words = read_token_file(f_p_outpath)
    b_sentence_list, b_word_num, b_words = read_token_file(b_p_outpath)

    print("\nForward packets information:")
    f_formats = format_info(f_sentence_list)
    print("\nBackward packets information:")
    b_formats = format_info(b_sentence_list)

    print("\n[out] Forward Main Protocol Format:")
    f_format_string = extract_main_format(f_formats, f_words)
    for stri, i in zip (f_format_string,range(len(f_format_string))):
        print("{0}. {1}".format(i + 1, stri))
    print("\n[out] Backward Main Protocol Format:")
    b_format_string = extract_main_format(b_formats, b_words)
    for stri, i in zip(b_format_string, range(len(b_format_string))):
        print("{0}. {1}".format(i + 1, stri))

    print("Infer protocol format successfully.")
    return f_format_string, b_format_string