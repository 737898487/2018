from PRO.preprocess_main import preprocess
from Re.bin import BinRe
import os


if __name__ == "__main__":

    data_path=input("Please input data_path:")    
    print(data_path)
    if  not os.path.exists("./cache"):
        os.mkdir("./cache")
    preprocess(data_path,"./cache")
    
    BinRe("./cache")

    os.rmdir("./cache")
    