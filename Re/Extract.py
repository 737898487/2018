"""
json 文件 
{
    name:应用名称，
    numsoftraffic:业务流个数，
    {
        port:
        {
            content:
            packetnums:
            offset:
            direction:
        },……
    }(一个业务流一个特征集)
}
"""
import os
import feature
import ngram
import json
import parse
import gl
import collections
from netzob.all import *
class Application:
    def __init__(self,application:str,data:dict(),sports=None,dports=None):
        self.name=application#应用名称
        self.data=data
        self.traffics=dict() #业务流个数
        self.sports=sports
        self.dports=dports
    
    def setTraffic(self):
        for key in self.data.keys():
            self.traffics[key]=Traffic(self.data[key])
        return 
    
    def setTrafficFea(self,isclus=True):
        for key in self.data.keys():
            if isclus:
            # self.traffics[key].GetAllFeas()
                self.traffics[key].GetAllFeasClus()
            else:
                self.traffics[key].GetAllFeas()
        return
        
    def tojson(self):
        res=dict()
        res["name"]=self.name
        # print(self.sports)
        # print(self.dports)
        if len(self.dports)<=4:
            res["dports"]=list(self.dports)
        if len(self.sports)<=4:
            res["sports"]=list(self.sports)
        for key in self.traffics.keys():
            k=key.split('/')[-1]
            res[k]=Transfrom (self.traffics[key].fea)
        json_res=json.dumps(res,indent=4,separators=(',',':'))
        f=open("./result/"+self.name+".json",'w')
        f.write(json_res)
        f.close()
    
class Traffic:
    def __init__(self,data):# data 为 key[1,2,3] value 为list()
        self.data=data
        self.fea=dict() # 无聚类特征
        self.fea_clus=dict() # 聚类特征


    def GetAllFeas(self):
    
        for key in self.data.keys():
            self.fea[key]=self.GetFea(self.data[key])
        return
    
    def GetAllFeasClus(self):
        for key in self.data.keys():
            self.fea_clus[key]=self.ParseList(self.data[key])
        return
    
    def GetFea(self,data:list):
        pkt=len(data)
        matrix=ngram.n_gram_matrix(data,1)
        fea_vector=self.GetFeaVet(matrix,pkt,0.90)
        # print(fea_vector)
        return fea_vector

    def GetFeaVet(self,matrix, pkt, threshold):
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
                if c / pkt >= threshold  and matrix[0][col_count]!='-' :
                    all_pkt+=c
                    if line_count not in fea_vector.keys():
                        fea_vector[line_count]=[matrix[0][col_count]]
                    else:
                        fea_vector[line_count].append(matrix[0][col_count])
                col_count += 1
            line_count += 1

        return fea_vector

    def ParseList(self,data:list):
        pcap_data=dict()
        for i in range(len(data)):
            pcap_data[i]=data[i]
        gl.res=dict()
        res=parse.Parse(pcap_data,0)
        features=dict()
        for key in res.keys():
            features[key]=TransfromAutomata(self.GetFea(res[key]))# key 为聚类名称
            print(features[key])
        rows=[]
        for seq in list(features.values()):
            rows.append(RawMessage(seq.encode('utf-8')))
        symbols = Format.clusterByAlignment(rows)
        # Format.splitAligned(len(symbols))
        Symbol
        for symbol in symbols:
            # f=str(symbol.fields.list[0].domain.dataType.value)
            # f.specialize()
            # da=set(f)
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray
            f=str(
                TypeConverter.convert(symbol.fields.list[0].domain.dataType.value, BitArray,Raw))
            print(f[3:-1])

        print("*"*50)
        return features

def TransfromAutomata(features:collections.OrderedDict()):
    feature=""
    positions=list(features.keys())
    if len(positions)==0:
        return "none"
    flag=positions[0]
    for position in positions:
        if position==flag:
            feature+=features[position][0]
            flag+=1
        else:
            feature+="-"+features[position][0]
            flag=position+1
    return feature    

def TransfromClus(feature):
    pass
def Transfrom(fea_vector:dict()):
    res=dict()
    count=0
    value_count=-1
    v=list(fea_vector.keys())
    for value in fea_vector.values():
        value_count+=1
        postions=list(value.keys())
        print(postions)
        if len(postions)==0:
            continue
        offset=postions[0]
        index=postions[0]
        fea_value=value[offset][0]
        for i  in range(1,len(postions)):
            if postions[i]-index==1 and len(value[postions[i]])==1:
                index=postions[i]
                fea_value=fea_value+value[postions[i]][0]
            else:
                res[count]={
                    "value":fea_value,
                    "offset":offset,
                    "packetnum":v[value_count]
                }
                count+=1
                fea_value=value[postions[i]][0]
                offset=postions[i]
                index=postions[i]            
            if i==len(postions)-1:
                res[count]={
                    "value":fea_value,
                    "offset":offset,
                    "packetnum":v[value_count]
                }
                count+=1
    return res






    


