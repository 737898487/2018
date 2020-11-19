

def preprocess(src_path,
               dst_path,
               remove=True,
               flow_packets=100):
        # new method(cluster)
        from .preprocess_2 import parse
        parse(src_path, dst_path, remove=remove, flow_packets=flow_packets)


if __name__ == '__main__':
    path = "D:\\协议逆向\\原始zip\\测试流量\\王者荣耀"
    path_dst = "D:\\协议逆向\\原始zip\\新建文件夹\\used"
    import time
    start = time.time()
    preprocess(path, path_dst)
    end = time.time()
    print("processing time:%.2f seconds" % (end - start))
