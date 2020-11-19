#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser
import os
from Text_Traffic_Analysis.Packet_Segment import pkt_seg_by_delimiters
from Text_Traffic_Analysis.Select_Words import top_words_set, select_key_words
from Text_Traffic_Analysis.Format_Extract import infer_protocol_format
from Text_Traffic_Analysis.Protocol_Feature import get_traffic_feature

# def if_file_exist(PATH):
#     overwrite_flag = False
#     while os.path.exists(PATH) and overwrite_flag is False:
#         print("File '"+PATH+"' exists, overwrite? y/n")
#         while True:
#             choice = input()
#             if choice == '' or choice == 'y':
#                 overwrite_flag = True
#                 break
#             elif choice == 'n':
#                 print("Re-PATH: ")
#                 PATH = input()
#                 break
#             else:
#                 print("Invalid Input(y/n):")
#     return PATH

print("[in] Configuration file path: ", end="")
cf_path = input().strip()
cf = configparser.ConfigParser()
cf.read(cf_path)
DATA_PATH = cf.get('path', 'DATA_PATH')
# path_file_number=glob.glob(DATA_PATH + '*.pcap') #获取当前文件夹下个数
# SIZE = len(path_file_number)
# SEG_OUT_PATH = cf.get('path', 'SEG_OUT_PATH')
# WORDS_PATH = cf.get('path', 'WORDS_PATH')
# P_OUT_PATH = cf.get('path', 'P_OUT_PATH')

# 分割符暂时保留
# delimiters = cf.get('parameter', 'delimiters')
# DELIM = delimiters.split('^') # 注意分隔符

# json相关参数
MODE = cf.get('parameter', 'mode')
NAME = cf.get('parameter', 'name')
run_file_path = './run_file'
result_file_path = './result'
if not os.path.isdir(run_file_path):
    os.mkdir(run_file_path)
if not os.path.isdir(result_file_path):
    os.mkdir(result_file_path)
SEG_OUT_PATH = './run_file/seg_' + NAME # + '_' + str(SIZE)
WORDS_PATH = './run_file/words_' + NAME # + '_' + str(SIZE)
P_OUT_PATH = './run_file/pattern_' + NAME # + '_' + str(SIZE)

print("Data directory path: ", DATA_PATH)
# print("Pcap Number: ", SIZE)

# # print("Segmented file output path: ", SEG_OUT_PATH)
# SEG_OUT_PATH = if_file_exist(SEG_OUT_PATH)
# # print("Words file output path: ", WORDS_PATH)
# WORDS_PATH = if_file_exist(WORDS_PATH)

first_words = pkt_seg_by_delimiters(DATA_PATH, SEG_OUT_PATH)

tagged_weighted_word = top_words_set(SEG_OUT_PATH, WORDS_PATH)

f_words, b_words, f_data, b_data = select_key_words(tagged_weighted_word, DATA_PATH, P_OUT_PATH, MODE)

f_formats, b_formats = infer_protocol_format(P_OUT_PATH)
# 协议自动逆向结束

# 基于逆向结果开始推断协议特征字符串
get_traffic_feature(NAME, f_formats, b_formats, f_data, b_data, DATA_PATH, MODE)
