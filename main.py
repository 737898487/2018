from PreProcess.preprocess_main import preprocess
from Re.bin import BinRe
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
    print(data_path)
    if not os.path.exists("./cache"):
        os.mkdir("./cache")
    preprocess(data_path, "./cache")

    BinRe("./cache")
    del_file("./cache")
    # os.rmdir("./cache")
