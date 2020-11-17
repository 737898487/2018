def n_gram_matrix(pcap_data_bin, n):# pcap_dict 2
    '''
    统计所有报文各个位置中各个值的次数 
    param：ordereddict key：count value：报文应用层前len长度内容
    param：ngrams长度  
    return： matrix 第一行为各个位置的值  后面依次为各个位置对应值的频率
    '''
    matrix = [[]]
    pkt=0
    if type(pcap_data_bin)== list:
        data=pcap_data_bin
    else:
        data=pcap_data_bin.values()
    for seq in data:
        for i in range(32):
            temp = seq[i:i+n]
            if pkt == 0: # 第一个包
                if not temp in matrix[0]:
                    matrix[0].append(temp)
                    matrix.append([])
                    for k in range(len(matrix[0]) - 1):
                        matrix[-1].append(0)
                    matrix[-1].append(1)
                    for line in matrix:
                        while len(line) < len(matrix[0]):
                            line.append(0)
                else:
                    matrix.append([])
                    for m in range(matrix[0].index(temp)):
                        matrix[i+1].append(0)
                    matrix[i+1].append(1)
                    while len(matrix[i+1]) != len(matrix[0]):
                        matrix[i+1].append(0)
                    for line in matrix:
                        while len(line) < len(matrix[0]):
                            line.append(0)
            else:
                if not temp in matrix[0]:
                    matrix[0].append(temp)
                    for line in matrix:
                        while len(line) < len(matrix[0]):
                            line.append(0)
                    try:
                        matrix[i + 1][matrix[0].index(temp)] += 1
                    except Exception as e:
                        while len(matrix) <= i+1:
                            matrix.append([0] * len(matrix[0]))
                        matrix[i + 1][matrix[0].index(temp)] += 1
                else:
                    try:
                        matrix[i+1][matrix[0].index(temp)] += 1
                    except Exception as e:
                        while len(matrix) <= i+1:
                            matrix.append([0] * len(matrix[0]))
                        matrix[i + 1][matrix[0].index(temp)] += 1
                    for line in matrix:
                        while len(line) < len(matrix[0]):
                            line.append(0)
        pkt+=1
    return matrix