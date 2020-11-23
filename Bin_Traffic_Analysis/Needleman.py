import sys
class Tree:
    def __init__(self):
        self._value=None
        self.flag=0
        self._rightNode=None
        self._leftNode=None
        self.rightGaps=None
        self.leftGaps=None
    def getRight(self):
        return self._rightNode
    
    def getLeft(self):
        return self._leftNode
    
    def getValue(self):
        return self._value
    
    def setRight(self,rightNode):
        self._rightNode=rightNode
    
    def setLeft(self,leftNode):
        self._leftNode=leftNode
    
    def setValue(self,seq):
        self._value=seq
    
    def setFlag(self):
        self.flag=1

def NeedlemanNodes(rightNode:Tree,leftNode:Tree,resultNode:Tree):
    resultNode.setRight(rightNode)
    resultNode.setLeft(leftNode)
    M=len(rightNode.getValue())+1
    N=len(leftNode.getValue())+1

    lcs=[[0 for i in range(N)] for i in range(M)]
    back=[[0 for i in range(N)] for i in range(M)]
    Continous=[[0 for i in range(N)]for i in range(M)]

    UP=0
    LEFT=1
    DIAGONAL=2
    STOP=3

    for i in range(M):
        lcs[i][0]=-2*i
        back[i][0]=LEFT    
    
    for i in range(N):
        lcs[0][i]=-2*i
        back[0][i]=UP
    for i in range(1,M):
        for j in range(1,N):
            q=0
            if rightNode.getValue()[i-1]==leftNode.getValue()[j-1]:
                Continous[i][j]=Continous[i-1][j-1]+1
                q=2+Continous[i-1][j-1]*2
                # q=2
            else:
                Continous[i][j]=0
                q=-1
            Max=max([lcs[i-1][j-1]+q,
                    lcs[i-1][j]-2,
                    lcs[i][j-1]-2])
            lcs[i][j]=Max
            if Max==lcs[i-1][j-1]+q:
                back[i][j]=DIAGONAL
            elif Max==lcs[i][j-1]-2:
                back[i][j]=UP
            elif Max==lcs[i-1][j]-2:
                back[i][j]=LEFT
    back[0][0]=STOP
    rightList=list()
    leftList=list()
    newRightSeq=b""
    newLeftSeq=b""
    i=M-1
    j=N-1
    
    while i>0 or j>0:
        if back[i][j]==DIAGONAL:
            newRightSeq=rightNode.getValue()[i-1].to_bytes(1,sys.byteorder)+newRightSeq
            newLeftSeq=leftNode.getValue()[j-1].to_bytes(1,sys.byteorder)+newLeftSeq
            i-=1
            j-=1
        elif back[i][j]==LEFT:
            newRightSeq=rightNode.getValue()[i-1].to_bytes(1,sys.byteorder)+newRightSeq
            newLeftSeq=b"_"+newLeftSeq
            i-=1
            leftList.append(j)
        elif back[i][j]==UP:
            newLeftSeq=leftNode.getValue()[j-1].to_bytes(1,sys.byteorder)+newLeftSeq
            newRightSeq=b"_"+newRightSeq
            j-=1
            rightList.append(i)
        elif back[i][j]==STOP:
            newRightSeq=rightNode.getValue()[i-1].to_bytes(1,sys.byteorder)+newRightSeq
            newLeftSeq=leftNode.getValue()[j-1].to_bytes(1,sys.byteorder)+newLeftSeq
            i-=1
            j-=1
    
    resultNode.rightGaps=rightList
    resultNode.leftGaps=leftList

    if len(rightList)>len(leftList):
        resultNode.setValue(newLeftSeq)
    else:
        resultNode.setValue(newRightSeq)
    
    return


def SmithWunsh(seq1:str,seq2:str)->float:
    M=len(seq1)+1
    N=len(seq2)+1
    res=0
    lcs=[[0 for i in range(N)] for i in range(M)]
    # back=[[0 for i in range(N)] for i in range(M)]
    # Continous=[[0 for i in range(N)]for i in range(M)]

    for i in range(M):
        lcs[i][0]=0*i
        # back[i][0]=LEFT    
    
    for i in range(N):
        lcs[0][i]=0*i
        # back[0][i]=UP
    for i in range(1,M):
        for j in range(1,N):
            q=0
            if seq1[i-1]==seq2[j-1]:
                # Continous[i][j]=Continous[i-1][j-1]+1
                # q=2+Continous[i-1][j-1]*2
                q=2
            else:
                # Continous[i][j]=0
                q=-1
            Max=max([lcs[i-1][j-1]+q,
                    lcs[i-1][j]-2,
                    lcs[i][j-1]-2],
                    0)
            res=max(Max,res)
            lcs[i][j]=Max
    return res

def GetResultSeqs(node:Tree(),resultSeqs:list(),gaps:list()):
    if node.getRight()!=None:
        gaps.append(node.rightGaps)
        GetResultSeqs(node.getRight(),resultSeqs,gaps)
        gaps.pop(-1)
    
    if node.getLeft()!=None:
        gaps.append(node.leftGaps)
        GetResultSeqs(node.getLeft(),resultSeqs,gaps)
        gaps.pop(-1)
    
    if node.getLeft()==None and node.getRight()==None:
        resultSeq=node.getValue()
        if len(gaps)==0:
            resultSeqs.append(resultSeq)
            return
        for i in range(len(gaps)-1,-1,-1):
            if len(gaps[i])>0:
                for c in gaps[i]:
                    resultSeq=resultSeq[0:c]+b"_"+resultSeq[c:]
        resultSeqs.append(resultSeq)
        return
    

    
def FindShort(nodes:list)->list:
    '''
    查找nodes中序列长度最短的两个node
    param：节点集合
    return: index of the two shortest nodes
    '''
    s1=sys.maxsize
    s2=sys.maxsize
    result=[0,0]
    if len(nodes)==2:
        return [0,1]
    for node in nodes:
        length=len(node.getValue())
        if length<s1 and node.flag==0:
            s2=s1
            s1=length
            result[1]=result[0]
            result[0]=nodes.index(node)
        elif length<s2 and node.flag==0:
            s2=length
            result[1]=nodes.index(node)
    nodes[result[0]].setFlag()
    nodes[result[1]].setFlag()
    return result
        

def Needleman(seqs:[str])->list:
    '''
    Needleman
    param:原始报文序列
    return:插入空格后的序列
    '''
    nodes=list()
    for seq in seqs:
        temp=Tree()
        temp.setValue(seq)
        nodes.append(temp)
    
    for i in range(len(seqs)-1):
        twoNodes=FindShort(nodes)
        nodes.append(Tree())
        NeedlemanNodes(nodes[twoNodes[0]],nodes[twoNodes[1]],nodes[-1])
    
    root=Tree()
    for node in nodes:
        if node.flag==0:
            root=node
    
    resultSeqs=list()
    gaps=list()

    GetResultSeqs(root,resultSeqs,gaps)

    return resultSeqs

if __name__ == "__main__":
    # seqs=["GGATCGA",
    # "GAATTCAGTTA",]
    f=open("./result/Row0-1")
    seqs=f.readlines()
    res=Needleman(seqs)
    for r in res:
        print(r)


    

        
        
    



