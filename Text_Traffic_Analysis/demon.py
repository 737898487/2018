#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser
import os
from Text_Traffic_Analysis.Packet_Segment import pkt_seg_by_delimiters
from Text_Traffic_Analysis.Select_Words import top_words_set, select_key_words
from Text_Traffic_Analysis.Format_Extract import infer_protocol_format
from Text_Traffic_Analysis.Protocol_Feature import get_traffic_feature

def Text_Re(DATA_PATH,MODE,NAME):

    run_file_path = './run_file'
    result_file_path = './result'
    if not os.path.isdir(run_file_path):
        os.mkdir(run_file_path)
    if not os.path.isdir(result_file_path):
        os.mkdir(result_file_path)
    SEG_OUT_PATH = './run_file/seg_' + NAME 
    WORDS_PATH = './run_file/words_' + NAME 
    P_OUT_PATH = './run_file/pattern_' + NAME 

    print("Data directory path: ", DATA_PATH)

    # 协议逆向开始
    first_words = pkt_seg_by_delimiters(DATA_PATH, SEG_OUT_PATH)

    tagged_weighted_word = top_words_set(SEG_OUT_PATH, WORDS_PATH)

    f_words, b_words, f_data, b_data = select_key_words(tagged_weighted_word, DATA_PATH, P_OUT_PATH, MODE)

    f_formats, b_formats = infer_protocol_format(P_OUT_PATH)

    # 基于逆向的报文格式推断协议特征字符串
    get_traffic_feature(NAME, f_formats, b_formats, f_data, b_data, DATA_PATH, MODE)
