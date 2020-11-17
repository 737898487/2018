import subprocess


class PcapSplitter:
    """分割 a .pcap """

    def __init__(self, pcap_path, exefile_path="PcapSplitter"):
        # 检查PcapSplitter.exe是否存在
        self._check_binary(exefile_path)
        self._exefile_path = exefile_path
        self._pcap_path = pcap_path

    def split_by_size(self, size_bytes, dest_path, pkts_bpf_filter=""):
        """按大小分割"""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "file-size", "-p", str(size_bytes), "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_count(self, count_pkts, dest_path, pkts_bpf_filter=""):
        """按包数量分割"""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "packet-count", "-p", str(count_pkts), "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_client_ip(self, dest_path, pkts_bpf_filter=""):
        """按客户端IP分割, 相同客户端IP的连接都会被分为一个pcap."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "client-ip", "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_server_ip(self, dest_path, pkts_bpf_filter=""):
        """按服务器IP分割, 相同服务器IP的连接都会被分为一个pcap."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "server-ip", "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_server_port(self, dest_path, pkts_bpf_filter=""):
        """按端口二元组分割, 相同的连接都会被分为一个pcap."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "server-port", "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_ip_src_dst(self, dest_path, pkts_bpf_filter=""):
        """按IP二元组分割, 相同的连接都会被分为一个pcap."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "ip-src-dst", "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_session(self, dest_path, pkts_bpf_filter=""):
        """按会话五元组分割, 每个会话都会被分为一个pcap"""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "connection", "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_filter(self, bpf_filter, dest_path, pkts_bpf_filter=""):
        """分割为2个pcap: 一个符合给出的 BPF filter (file #0) 一个为剩下不满足的 (file #1)."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "bpf-filter", "-p", bpf_filter, "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def split_by_round_robin(self, n_files, dest_path, pkts_bpf_filter=""):
        """split the file in a round-robin manner - each packet to a different 
        file."""
        args = (self._exefile_path, "-f", self._pcap_path, "-o", dest_path,
                "-m", "round-robin", "-p", str(n_files), "-i", pkts_bpf_filter)
        # Execute the PcapSplitter binary
        return self._execute(args).decode()

    def _execute(self, args):
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        return popen.stdout.read()

    def _check_binary(self, exefile_path):
        try:
            subprocess.Popen(exefile_path, stdout=subprocess.PIPE)
        except FileNotFoundError:
            print("ERROR: 未找到PcapSplitter.exe\n")


