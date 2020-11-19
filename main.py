from PreProcess.preprocess_main import preprocess
from Re.bin import BinRe
from Text_Traffic_Analysis.demon import Text_Re
import os



def del_file(path):
    ls = os.listdir(path)
    for i in ls:
        c_path = os.path.join(path, i)
        if os.path.isdir(c_path):
            del_file(c_path)
        else:
            os.remove(c_path)
    os.rmdir(path)

if __name__ == "__main__":

    data_path = input("Please input data_path:")
    name=input("Please input the name of application:") 
    mode=input("common or app:")
    print(data_path)
    pre_output="./cache"
    if not os.path.exists(pre_output):
        os.mkdir(pre_output)
    preprocess(data_path, pre_output)

    BinRe(pre_output,name)
   
    if os.path.exists(os.path.join(pre_output,"text_tcp/0/")):
        Text_Re(os.path.join(pre_output,"text_tcp/0/"),mode,name)
    # del_file("./cache")
    # os.rmdir("./cache")
