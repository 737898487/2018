

def preprocess(src_path,
               dst_path,
               app_name=None,
               method=2,
               keep_only_app=False,
               remove=False,
               flow_packets=100):
    if method == 1:
        # old method
        from preprocess_1 import parse
        parse(src_path, dst_path, app_name, keep_only_app=keep_only_app, remove=remove, flow_packets=flow_packets)
    else:
        # new method(cluster)
        from preprocess_2 import parse
        parse(src_path, dst_path, remove=remove, flow_packets=flow_packets)


if __name__ == '__main__':
    path = "D:\\协议逆向\\原始zip\\新建文件夹\\youku"
    path_dst = "D:\\协议逆向\\原始zip\\新建文件夹\\used"
    preprocess(path, path_dst, app_name="youku")
