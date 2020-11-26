from Pre_Process.Pre_Process_Entrance import Pre_Process
from Bin_Traffic_Analysis.Bin_Entrance import Bin_Re
from Text_Traffic_Analysis.Text_Entrance import Text_Re
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
    data_path = input("Please input traffic_path:")
    name = input("Please input the name of application:")
    mode = input("Please input the type of traffic(common or app):")
    pre_output="./cache"
    if not os.path.exists(pre_output):
        os.mkdir(pre_output)
    Pre_Process(data_path, pre_output)

    run_file_path = './run_file'
    result_file_path = './result'
    if not os.path.isdir(run_file_path):
        os.mkdir(run_file_path)
    if not os.path.isdir(result_file_path):
        os.mkdir(result_file_path)

    Bin_Re(pre_output, name)
    Text_Re(pre_output, mode, name)

    del_file("./run_file")
    del_file("./cache")