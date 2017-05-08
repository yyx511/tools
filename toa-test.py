# -*- coding: utf-8 -*-
#!/usr/bin/python

#TCPOption支持自定义选项修改
#文件ImpactPacket.py->TCPOption类的__init__函数末尾添加如下代码
# else:
#	PacketBuffer.__init__(self, 2)
#	self.set_kind(kind)

# 用法
#	opt = ImpactPacket.TCPOption(100) #选项好为100的选项
#	opt.set_len(4) #选项的长度：选项号1个字节+长度1个字节+值2个字节
#	opt.set_word(2, 100) #选项的值为100,占用2个字节


import socket
import time
from impacket import ImpactDecoder, ImpactPacket

SRC_HOST = '192.168.40.4'
SRC_PORT = 50001
DST_HOST = '13.1.1.1'
DST_PORT = 80

#IP
ip = ImpactPacket.IP()
ip.set_ip_src(SRC_HOST)
ip.set_ip_dst(DST_HOST)

#tcp SYN
tcp = ImpactPacket.TCP()
tcp.set_th_sport(SRC_PORT)
tcp.set_th_dport(DST_PORT)
tcp.set_th_seq(9000)
tcp.set_th_ack(0)
tcp.set_SYN()
tcp.set_th_win(29200)
#tcp opt
'''
#用例1#######################################################################
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_TIMESTAMP, 50000) #10
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_TIMESTAMP, 50000) #10
tcp.add_option(opt)
'''
'''
#用例2#######################################################################
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
###############################################################################
'''
'''
#用例3
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(101) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 101)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(102) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 102)
tcp.add_option(opt)
'''
'''
#用例4
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
'''
'''
#用例5
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
'''
'''
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK)
opt.set_len(2 + 2 * 4)
opt.set_left_edge(1000)
opt.set_right_edge(2460)
opt.set_left_edge(4000)
opt.set_right_edge(4460)
tcp.add_option(opt)
'''
ip.contains(tcp)

sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sk.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #加上，让内核去算checksum
sk.sendto(ip.get_packet(), (DST_HOST, DST_PORT))

#收syn+ack包
r_ip_pkt, addr = sk.recvfrom(4096)
r_ip = ImpactDecoder.IPDecoder().decode(r_ip_pkt)
r_tcp = r_ip.child()
print "ip.dst=", r_ip.get_ip_dst()
print "tcp.sport=", r_tcp.get_th_sport()
print "tcp.flags=", r_tcp.get_th_flags()

#发送push+ack包
#ip
ip = ImpactPacket.IP()
ip.set_ip_src(SRC_HOST)
ip.set_ip_dst(DST_HOST)

#tcp(push+ack)
tcp = ImpactPacket.TCP()
tcp.set_th_sport(SRC_PORT)
tcp.set_th_dport(DST_PORT)
tcp.set_th_seq(r_tcp.get_th_ack())
tcp.set_th_ack(r_tcp.get_th_seq() + 1)
tcp.set_ACK()
tcp.set_PSH()
tcp.set_th_win(29200)
n = 90
'''
#ACK+PSH用例1
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
'''
'''
#ACK+PSH用例2
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(101) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 101)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(102) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 102)
tcp.add_option(opt)
'''
'''
#ACK+PSH用例3
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
'''
'''
#ACK+PSH用例4
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
'''
'''
#ACK+PSH用例5
#(n=1401) + 20 + 20 + 36 + 10 + 13 = 1500
n=1401
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
'''
'''
#ACK+PSH用例6
#(n=1397) + 20 + 20 + 39 + 1 + 10 + 13 = 1500
n=1397
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(101) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 101)
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(102) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 102)
tcp.add_option(opt)
'''
'''
#ACK+PSH用例7
#(n=1397) + 20 + 20 + 39 + 1 + 10 + 13 = 1500
n=1397
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(100) #自定义选项,长度4
opt.set_len(4)
opt.set_word(2, 100)
tcp.add_option(opt)
'''

#ACK+PSH用例8
#(n=1425) + 20 + 20 + 39 + 1 + 10 + 13 = 1500
n=1425
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, 1460) #4
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, 8) #3
tcp.add_option(opt)
opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED) #2
tcp.add_option(opt)

msg = "GET/?ucid=%s HTTP/1.1\r\n\r\n" % ('a' * n)
tcp.contains(ImpactPacket.Data(msg))
ip.contains(tcp)
sk.sendto(ip.get_packet(), (DST_HOST, DST_PORT))


sk.close()
