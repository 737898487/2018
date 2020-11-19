import dpkt
import socket

RST_MAXLEN = 1460
LOST_MAXLEN = 5 * 1460

class Packet(object):

    def __init__(self, ts, data):
        try:
            self.ts = ts
            self.data = data
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            self.seq = ip.data.seq
            self.next_seq = len(ip.data.data) + self.seq + (ip.data.flags & dpkt.tcp.TH_SYN != 0)
            self.ack = ip.data.ack
            self.src = ip.src
            self.dst = ip.dst
            self.sport = ip.data.sport
            self.dport = ip.data.dport
            self.p = ip.p
        except:
            self.ts = ts

    def __eq__(self, other):
        return (self.seq == other.seq and self.next_seq == other.next_seq
                    and self.ack == other.ack and self.src == other.src
                        and self.dst == other.dst and self.sport == other.sport
                            and self.dport == other.dport)


def retimestamp(packets):
    ts_list = [p.ts for p in packets]
    ts_list.sort()
    new_packets = [Packet(t, p.data) for t, p in zip(ts_list, packets)]
    return new_packets


def check_flow_complete(packets):
    if len(packets) == 1:
        # return True
        return packets

    def lost_pkt(pkt_a, pkt_b):
        pkt = Packet((pkt_a.ts + pkt_b.ts) / 2, "")

        pkt.seq = pkt_a.next_seq
        pkt.next_seq = pkt_b.seq
        pkt.src = pkt_a.src
        pkt.dst = pkt_a.dst
        pkt.sport = pkt_a.sport
        pkt.dport = pkt_a.dport
        pkt.p = pkt_a.p
        return pkt
    if len(packets) > 0:
        packets_new = [packets[0]]
    else:
        return packets
    for i in range(1, len(packets)):
        if packets[i].seq != packets[i-1].next_seq:
            eth = dpkt.ethernet.Ethernet(packets[i-1].data)
            ip = eth.data
            if ip.data.flags & dpkt.tcp.TH_RST != 0:
                packets_new.append(packets[i])
                continue
            if packets[i].seq - packets[i - 1].next_seq > LOST_MAXLEN:
                break
            packets_new.append(lost_pkt(packets[i-1], packets[i]))
            # return False
        packets_new.append(packets[i])
    return packets_new


def recombine_pkt(filename):
    stream_ordered = {}
    biflow = {}
    j = 0
    if_rst = {'s2d': 0, 'd2s': 0}
    with open(filename, 'rb') as f:
        capture = dpkt.pcap.Reader(f)

        for timestamp, packet in capture:
            current = Packet(timestamp, packet)
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            j += 1
            conn = '{0}_{1}_{2}_{3}_{4}'.format(socket.inet_ntoa(current.src),
                                                          socket.inet_ntoa(current.dst),
                                                          current.sport,
                                                          current.dport, current.p)
            if conn in stream_ordered.keys():
                ordered = stream_ordered[conn]
                direction = 's2d'
            else:
                conn = '{0}_{1}_{2}_{3}_{4}'.format(socket.inet_ntoa(current.dst),
                                                              socket.inet_ntoa(current.src),
                                                              current.dport,
                                                              current.sport, current.p)
                if conn in stream_ordered.keys():
                    ordered = stream_ordered[conn]
                    direction = 'd2s'

                else:
                    conn = '{0}_{1}_{2}_{3}_{4}'.format(socket.inet_ntoa(current.src),
                                                        socket.inet_ntoa(current.dst),
                                                        current.sport,
                                                        current.dport, current.p)
                    stream_ordered[conn] = {'s2d':[], 'd2s':[], 's2d_next_seq':0, 'd2s_next_seq':0}
                    ordered = stream_ordered[conn]
                    direction = 's2d'

            if len(ordered[direction]) == 0:
                ordered[direction].append(current)
                ordered[direction + '_next_seq'] = current.next_seq

            if current.seq >= ordered[direction + '_next_seq']:
                # if check_dup(current, ordered[direction]):
                if current not in ordered[direction]:
                    ordered[direction].append(current)
                    ordered[direction + '_next_seq'] = current.next_seq
                else:
                    continue
            else:
                if current in ordered[direction]:
                    continue
                temp_ordered = ordered[direction]
                for i in range(len(temp_ordered) - 1, -1, -1):
                    if current.seq < temp_ordered[i].seq and i > 0:  # not first pkt
                        continue
                    else:
                        try:
                            current.ts = (temp_ordered[i].ts + temp_ordered[i - 1].ts) / 2  # modify the timestamp of out of order pkt
                            ordered[direction].insert(i + 1, current)
                            break
                        except:
                            print("8")

    for conn, ordered in stream_ordered.items():
        biflow[conn] = check_flow_complete(ordered['s2d']) + check_flow_complete(ordered['d2s'])
        biflow[conn].sort(key=lambda x: x.ts)
    
    return biflow


def write_biflow_to_file(filename):
    try:
        biflow = recombine_pkt(filename)
        for conn in biflow.keys():
            f = open(filename, 'wb')
            writer = dpkt.pcap.Writer(f)
            for p in biflow[conn]:
                if p.data == "":
                    continue
                writer.writepkt(pkt=p.data, ts=p.ts)
    except Exception as e:
        print(e)