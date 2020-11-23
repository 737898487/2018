def hex_2_dec(str):
    '''
    单个十六进制字符转十进制int
    :param str:
    :return:
    '''
    try:
        return int(str)
    except Exception as e:
        if str == 'a':
            return 10
        elif str == 'b':
            return 11
        elif str == 'c':
            return 12
        elif str == 'd':
            return 13
        elif str == 'e':
            return 14
        else:
            return 15

def printable(hex_list):
    '''
    判断一个十六进制序列中的可打印ascii码占比
    :param hex_list:
    :return:
    '''
    count_printable = 0
    try:
        for i in range(len(hex_list) // 2):
            temp_num = 16 * hex_2_dec(hex_list[2 * i]) + hex_2_dec(hex_list[2 * i + 1])
            if temp_num == 13 or temp_num == 10 or (temp_num > 31 and temp_num < 128):
                count_printable += 1
    except Exception as e:
        print(e)
    finally:
        if len(hex_list) != 0:
            r = count_printable / (len(hex_list) // 2)
            success = (r == 1.0)
        else:
            return(False, 0.0)
    return (success, r)