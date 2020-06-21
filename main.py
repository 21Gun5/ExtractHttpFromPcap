import os
import struct
# import scapy
# import scapy_http.http as http
# from scapy.all import *


def get_string(data, start, end):
	if data.upper().find(start.upper())== -1:
		return ""
	temp = data[data.upper().find(start.upper())+len(start):]
	if temp.upper().find(end.upper())== -1:
		return ""
	value = temp[:temp.upper().find(end.upper())]
	return value

# 此法不准确，弃用
def get_info_via_scapy(pcap_file):
    packets = rdpcap(pcap_file)
    info_list = []
    for packet in packets:
        if packet.haslayer(http.HTTPRequest):
            http_header = packet[http.HTTPRequest].fields
            # print(http_header)
            info  = (
                str(http_header['Method']).replace("b'","").replace("'",""),
                str(('http://' + str(http_header['Host']) + str(http_header['Path'])).replace("b'","").replace("'",""))
            )
            # print(info)
            info_list.append(info)

    return list(set(info_list))

def get_info_via_content(pcap_file):
    # pass
    fp = open(pcap_file,'rb')
    # 24 bytes pcap header
    pcap_header = fp.read(24)
    (magic_number,version_major,version_minor,thiszone,sigfigs,snaplen,network) = struct.unpack("IHHIIII",pcap_header)
    print("pcap header: %x %x %x %x %x %x %x"%(magic_number,version_major,version_minor,thiszone,sigfigs,snaplen,network))

    # 16 bytes packet header
    packet_header = fp.read(16)

    packet_count = 0
    http_count = 0
    info_list = []
    while packet_header:
        (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack("IIII", packet_header)

        # print("packet_%d header: %x %x %x %x"%(i,ts_sec,ts_usec,incl_len,orig_len))
        # 14 bytes link layernk
        # link_layer = fp.read(16)  # here
        # print(link_layer)#here
        # (dst_mac,src_mac,tmp,type) = struct.unpack("6c6c2c2c",link_layer)#here
        # ip_layer = fp.read(20)
        # tcp_layer = fp.read(20)
        # http_layer = fp.read(incl_len - 16 - 16 - 20 - 20)
        # print(incl_len - 16 - 16 - 20 - 20)
        # print(http_layer)
        # (method, path) = get_string(str(http_layer), "b'", "HTTP").split(" ", 1)
        # host = get_string(str(http_layer), "Host: ", "\r")
        # info = (method, ('http://' + host + path).strip())
        # print(info)

        packet_data = str(fp.read(incl_len))
        if packet_data.find("GET /") > -1:
            http_count += 1
            method = "GET"
            host = get_string(packet_data,"host: ",r"\r\n")
            path = get_string(packet_data,"GET "," HTTP")
            info = ("in_packet_%d"%packet_count, method, ('http://' + host + path).strip())
            # print(info)
            info_list.append(info)
        elif packet_data.find("POST /") > -1:
            http_count += 1
            method = "POST"
            host = get_string(packet_data,"host: ",r"\r\n")
            path = get_string(packet_data,"POST "," HTTP")
            info = ("in_packet_%d"%packet_count, method, ('http://' + host + path).strip())
            # print(info)
            info_list.append(info)
        else:
            print("http not found in packet_%d"%packet_count)

        # fp.seek(incl_len,1)# skip packet data
        packet_header = fp.read(16)
        packet_count += 1

    fp.close()
    # print(len(info_list), len(list(set(info_list))))
    print("packets: %d, http: %d\n"%(packet_count,http_count))

    return list(set(info_list))

def parse_pcap_format(pcap_file):
    pass

def save_file(file,info_list):
    get_num = 0
    post_num = 0
    fp = open(file, "a")
    for i in info_list:
        if i[1] == "GET":
            get_num += 1
        else:
            post_num += 1
        fp.write("%-3d\t%-15s\t%-6s\t%s\n" % (info_list.index(i)+1, i[0],i[1],i[2]))
        # print(i)
    fp.write("\ntotal: %d, post: %d, get: %d\n" % (len(info_list),get_num, post_num))
    fp.close()


if __name__ == '__main__':
    pcap_files = os.listdir("pcap")
    # file = pcap_files[0]
    # info_list = get_info_via_content("pcap/" + file)
    # for i in info_list:
    #     print(i)

    for file in pcap_files:
        if file.find(".pcap") == -1:
            continue
        print(file)
        info_list = get_info_via_content("pcap/" + file)
        output_file = "output/" + get_string("pcap/" + file, "/", ".") + ".txt"
        save_file(output_file, info_list)

