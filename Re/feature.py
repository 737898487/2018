import collections
import numpy as  np
from sklearn.metrics import silhouette_score
def GetFeaVet(matrix, pkt, threshold):
    '''
    根据matrix 筛选出每个位置的频繁项以及记录每个频繁项的频率
    param：matrix
    param: 总报文数
    param：频繁项阈值
    return：fea_vector key:position value：[(频繁项，频率)，……]
    '''
    fea_vector = collections.OrderedDict()
    line_count = 1 # 行
    all_pkt_p=list()
    count=3
    for line in matrix[1:]:
        col_count = 0 # 列
        all_pkt=0
        for c in line:
            if c / pkt >= threshold and c / pkt < 1 and matrix[0][col_count]!='--' :
                all_pkt+=c
                if line_count not in fea_vector.keys():
                    fea_vector[line_count]=[[matrix[0][col_count],c/pkt]]
                else:
                    fea_vector[line_count].append([matrix[0][col_count],c/pkt])
            col_count += 1
        line_count += 1

    return fea_vector

def GetAllVet(pcap_data, fea_vector, len_weight):
    '''
    根据各个位置的频繁项提取每个报文的特征向量
    param：报文 ordereddict key：count value：报文应用层内容
    param：频繁项 orderdict key：position value：[(频繁项，频率)，……]
    param：长度权重
    return X 特征向量集
    '''
    import math
    X = []
    length=0
    for value in fea_vector.values():
        length+=len(value)

    for seq in list(pcap_data.keys()):
        each = [0] * (length + 1)
        count = 0 
        for keys,values in fea_vector.items():
            for i in range(len(values)):
                if pcap_data[seq][keys-1:keys-1+len(values[i][0])]==values[i][0]:
                    each[count] = 1
                count +=1
        if len(fea_vector)>=5:                 
            each[-1] = math.sqrt((len(pcap_data[seq]) / 2)) / 10 * len_weight # 长度字段作为特征
        else:
            each[-1]=0
        X.append(each)

    X = np.array(X)
    
    return X

def Clusters(pcap_data,X,nums_itor,max_clus=15):
    '''
    根据X进行聚类
    param:报文
    param：特征向量集
    param：最大聚类数
    param:迭代次数
    return: dict key：子类名称(1,2,3……) value：子类报文集
    '''
    res_list = []
    max_sil = 0   #最大轮廓系数
    num = 0       # 最终聚类数
    final_y = np.array([]) #聚类结果
    for n in range(2, max_clus):
        res = KmeansMy(X, n)
        if sum(res)==0:
            final_y=res
            break
        res_list.append(res)
        temp = silhouette_score(X, res, metric='euclidean')
        # if temp <max_sil:
        #     break
        if temp > max_sil:
            max_sil = temp
            num = n 
            final_y = res
        # print(n, '  ', temp)
     

    split_dict = {}
    pkt_list = []
    for pkt in pcap_data.values():
        pkt_list.append(pkt)    

    for i in range(len(pkt_list)):
        if str(nums_itor)+"-"+str(final_y[i]) not in split_dict:
            split_dict[str(nums_itor)+"-"+str(final_y[i])] = [pkt_list[i]]
        else:
            split_dict[str(nums_itor)+"-"+str(final_y[i])].append(pkt_list[i])    
    return split_dict

def KmeansMy(X, clus_num):
    from sklearn.cluster import KMeans
    
    try:
        kmeans = KMeans(n_clusters = clus_num)
    except:
        pass
    kmeans.fit(X)
    res = kmeans.predict(X)
    return res

# def GetFeaVet(matrix, matrix_reverse,pkt, threshold):
#     fea_vector = collections.OrderedDict()
#     filter_vector=collections.OrderedDict()
#     itor_vector=collections.OrderedDict()
#     line_count = 1
#     all_pkt_p=list()
#     count=3
#     for line in matrix[1:]:
#         row_count = 0
#         all_pkt=0
#         for c in line:
#             if c / pkt >= threshold and c / pkt < 1 and matrix[0][row_count]!='--' :
#                 all_pkt+=c
#                 if line_count not in fea_vector.keys():
#                     fea_vector[line_count]=[matrix[0][row_count]]
#                 else:
#                     fea_vector[line_count].append(matrix[0][row_count])
#             row_count += 1

#         if all_pkt!=0 :
#             if  all_pkt/pkt<0.95 and all_pkt/pkt>0.5 and count>0:
#                 itor_vector[line_count]=fea_vector[line_count]
#                 print(count)
#             if all_pkt/pkt>=0.95 and all_pkt/pkt!=1.0:
#                 filter_vector[line_count]=fea_vector[line_count]
#             count-=1
#             all_pkt_p.append(all_pkt/pkt)
#         line_count += 1

#     line=-1
#     count=3
#     for line_reverse in matrix_reverse[1:]:
#         row=0
#         all_pkt_re=0
#         for c_reverse in line_reverse:
#             if c_reverse/pkt>=threshold and c_reverse/pkt<0.99 and matrix_reverse[0][row]!='--' :
#                 all_pkt_re+=c_reverse
#                 if line not in fea_vector.keys():
#                     fea_vector[line]=[matrix_reverse[0][row][::-1]]
#                 else:
#                     fea_vector[line].append(matrix_reverse[0][row][::-1])
#             row+=1

#         if all_pkt_re!=0:
#             if all_pkt_re/pkt>=0.95 and all_pkt_re/pkt!=1.0:
#                 filter_vector[line]=fea_vector[line]
#             # if all_pkt_re/pkt<0.95 and all_pkt_re/pkt>=0.5 and count>0:
#             #     itor_vector[line]=fea_vector[line]
#             #     print(count)
#             count-=1
#             all_pkt_p.append(all_pkt_re/pkt)
#         line-=1
#     count=0
#     for item in fea_vector.items():
#         print(str(item[0])+":"+str(item[1])+str(all_pkt_p[count])+'\n')
#         count+=1
#     return fea_vector, filter_vector ,itor_vector