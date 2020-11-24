import os
import sys
import Bin_Traffic_Analysis.Cluster_Feature as feature
import Bin_Traffic_Analysis.Ngram as ngram
import json
import Bin_Traffic_Analysis.Bin_Traffic_Parse as parse
import Bin_Traffic_Analysis.Global_Var as gl
import collections
import Bin_Traffic_Analysis.Needleman as Needleman
from netzob.all import *
from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
from netzob.Model.Vocabulary.Types.BitArray import BitArray


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
        res=collections.OrderedDict()
        res["name"]=self.name
        if len(self.dports)<=4:
            res["dports"]=list(self.dports)
        if len(self.sports)<=4:
            res["sports"]=list(self.sports)
        for key in self.traffics.keys():
            k=key.split('/')[-2]+key.split('/')[-1]
            res[k]=self.traffics[key].fea_clus
        json_res=json.dumps(res,indent=4,separators=(',',':'))
        f=open("./result/bin_"+self.name+".json",'w')
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
        fea_vector=self.GetFeaVet(matrix,pkt,0.95)
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
        # all_pkt_p=list()
        # count=3
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
            # if len(res[key])>3:
            # Revalues=TransfromAutomata(self.GetFea(Needleman.Needleman(res[key])))# key 为聚类名称
            Revalues=TransfromAutomata(self.GetFea(res[key]))# key 为聚类名称
            if len(Revalues)>0:
                features[key]=Revalues
                # print(features[key])
                # gl.sum+=len(res[key])

        rows=[]
        out=[]
        if len(features)>1:
            for seq in list(features.values()):
                if seq!="none":
                    rows.append(RawMessage(seq))
                else:
                    out.append(seq)
            symbols = Format.clusterByAlignment(rows,minEquivalence=50)
            # Format.splitAligned(len(symbols))
            # print("-"*20)
            for symbol in symbols:
                fs=b""
                l=symbol.fields.list
                for d in l:
                    if d.domain.dataType.value:
                        f=TypeConverter.convert(d.domain.dataType.value, BitArray,Raw)
                        fs+=isvalid(f) 
                    else:
                        if len(fs)==0 or fs[-1]!=45 :
                            fs+=b"--"
                print(fs)
                out.append(convert(fs))
        else:
            f=list(features.values())[0]
            if f=="none":
                out.append(f)
            else:
                out.append(convert(isvalid(f)))

        print("*"*50)
        out=Feature_optimization(out)
        return out

def TransfromAutomata(features:collections.OrderedDict()):
    feature=b""
    positions=list(features.keys())
    if len(positions)==0:
        return "none"
    flag=positions[0]
    for position in positions:
        if position==flag:
            feature+=features[position][0]
            flag+=1
        else:
            feature+=b"-"+features[position][0]
            flag=position+1
    return feature    

def isvalid(feature:str):
    def modify(feature):
        if feature.count(b"\x00")==len(feature):
            return b""
        # if len(feature)>6:
        #     return feature[0:6]
        # else:
        return feature
    ps=feature.split(b"-")
    f=[]
    for  p in ps:
        if len(p)>0:
            f.append(p)
    if len(f)==0:
        return b""
    if len(f)==1:
        return modify(f[0])
    else:
        res=modify(f[0])
        for i in range(1,len(f)):
            if len(modify(f[i]))>0:
                res+=b"--"+modify(f[i])
        return res


def Feature_optimization(features:list):
    
    res=list(set(features))
    
    return  res

def convert(fea):
    res=""
    for f in fea:
        if f==45:
            res+="-"
        else:
            res+=f.to_bytes(1,sys.byteorder).hex()
    return res




    


