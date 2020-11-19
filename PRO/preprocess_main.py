

def preprocess(src_path,
               dst_path,
               remove=True,
               flow_packets=100):
        # new method(cluster)
<<<<<<< HEAD
        from PRO.preprocess_2 import parse
        parse(src_path, dst_path, remove=remove, flow_packets=flow_packets)
=======
        from preprocess_2 import parse
        parse(src_path, dst_path,  remove=remove, flow_packets=flow_packets)
>>>>>>> 5361092b1ce595664c3b6c44d898814129d7f6d9


if __name__ == '__main__':
    path = "D:\\协议逆向\\原始zip\\测试流量\\王者荣耀"
    path_dst = "D:\\协议逆向\\原始zip\\新建文件夹\\used"
    import time
    start = time.time()
    preprocess(path, path_dst)
    end = time.time()
    print("processing time:%.2f seconds" % (end - start))
