from Bin_Traffic_Analysis.Ngram import n_gram_matrix
from Bin_Traffic_Analysis.Cluster_Feature import GetFeaVet, GetAllVet, Clusters
from Bin_Traffic_Analysis.Read_Pcap import ReadPcapHex
import Bin_Traffic_Analysis.Global_Var as gl

def Parse(pacp_data,nums_itor):
    '''
    parse 迭代式的去噪与报文聚类
    param:原始报文 dict key：count value：报文内容
    param:迭代的次数
    return dict key：子类名称 value：子类报文
    '''
    # 参数定义
    # global subclass_collection
    # global res
    pkt_num=len(pacp_data)
    print(pkt_num)
    

    #提取特征
    matrix=n_gram_matrix(pacp_data,1)
    fea_vec=GetFeaVet(matrix,pkt_num,gl.threshold_ofen)


    #去噪与分割报文
    clu_pkts,itor_pkts=Denoising(pacp_data,fea_vec)

    #聚类
    pkt_num_clus=len(clu_pkts)
    matrix_clu=n_gram_matrix(clu_pkts,1)
    fea_vec_clus=GetFeaVet(matrix_clu,pkt_num_clus,gl.threshold_ofen)
    X=GetAllVet(clu_pkts,fea_vec_clus,4)
    res_clus=Clusters(clu_pkts,X,nums_itor)
    print(len(clu_pkts),len(itor_pkts))
    #结果合并
    gl.res.update(res_clus)
    
    #进行迭代
    if len(itor_pkts)>100 and nums_itor<4:
        Parse(itor_pkts,nums_itor+1)
    return gl.res








def  Denoising(pacp_data,fea_vec):
    '''
    去除噪音 以及 分割报文
    param：dict 报文
    param：频繁项 dict key：position value：(频繁项，频率)
    return 两个报文集 聚类报文集 以及 迭代报文集
    '''
    #计算去噪与分割报文位置
    denoise=dict()
    itor=dict()
    for item in fea_vec.items():
        all_frequency=0.0
        position=item[0]
        fre=[]
        for value in item[1]:
            all_frequency+=value[1]
            fre.append(value[0])
        print(str(position)+":"+str(all_frequency)+" ",fre)
        if all_frequency>gl.threshold_denoise:
            denoise[position]=fre
        if all_frequency>gl.threshold_itor and all_frequency<gl.threshold_denoise and position < 5:
            itor[position]=fre
    # 去除噪声
    if len(denoise) !=0 :
        for count in list(pacp_data.keys()):
            for pos in denoise.keys():
                if pacp_data[count][pos-1:pos-1+gl.ngrams_len] not in denoise[pos]:
                    pacp_data.pop(count)
                    break
    
    clu_pkts=dict()
    itor_pkts=dict()
    
    #分割报文
    if len(itor)!=0:
        for count in list(pacp_data.keys()):
            for pos in itor.keys():
                if pacp_data[count][pos-1:pos-1+gl.ngrams_len] not in itor[pos]:
                    itor_pkts[count]=pacp_data[count]
                    break
                else:
                    clu_pkts[count]=pacp_data[count]
    else:
        clu_pkts=pacp_data
    #释放原来dict内存
    del pacp_data
    return  clu_pkts,itor_pkts

    
