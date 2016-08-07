#!/usr/bin/python

# 用法：./pcap-parser_3.py test.pcap www.baidu.com
import sys
import socket
import struct

filename = sys.argv[1]
url = sys.argv[2]

file = open(filename, "rb") 

pcaphdrlen = 24
pkthdrlen=16
linklen=14
iphdrlen=20
tcphdrlen=20
stdtcp = 20
layerdict = {'FILE':0, 'MAXPKT':1, 'HEAD':2, 'LINK':3, 'IP':4, 'TCP':5, 'DATA':6, 'RECORD':7}

files4out = {}

# Read 24-bytes pcap header
datahdr = file.read(pcaphdrlen)
(tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", datahdr)

if lt == 0x71:
	linklen = 16
else:
	linklen = 14

# Read 16-bytes packet header
data = file.read(pkthdrlen)

while data:
	ipsrc_tag = 0
	ipdst_tag = 0
	sport_tag = 0
	dport_tag = 0

	(sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)

	# read link
	link = file.read(linklen)
	
	# read IP header
	ipdata = file.read(iphdrlen)
	(vl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr) = struct.unpack(">ssHHHssHLL", ipdata)
	iphdrlen = ord(vl) & 0x0F 
	iphdrlen *= 4

	# read TCP standard header
	tcpdata = file.read(stdtcp)	
	(sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)
	tcphdrlen = pad1 & 0xF000
	tcphdrlen = tcphdrlen >> 12
	tcphdrlen = tcphdrlen*4

	# skip data
	skip = file.read(iplensave-linklen-iphdrlen-stdtcp)
	content = url
	FLAG = 0
	
	if skip.find(content) <> -1:
		FLAG = 1

	src_tag = socket.inet_ntoa(struct.pack('i',socket.htonl(saddr)))
	dst_tag = socket.inet_ntoa(struct.pack('i',socket.htonl(daddr)))
	sp_tag = str(sport)
	dp_tag = str(dport)

	# 此即将四元组按照固定顺序排位，两个方向变成一个方向，保证四元组的唯一性
	if saddr > daddr:
		temp = dst_tag
		dst_tag = src_tag
		src_tag = temp
	if sport > dport:
		temp = sp_tag
		sp_tag = dp_tag
		dp_tag = temp
	
	name = src_tag + '_' + dst_tag + '_' + sp_tag + '_' + dp_tag + '.pcap'
	# 这里用到了字典和链表，这两类加一起简直了
	if (name) in files4out:
		item = files4out[name]
		fi = 0
		cnt = item[layerdict['MAXPKT']]
		# 我们预期HTTP的GET请求在前6个数据包中会到来
		if cnt < 6 and item[layerdict['RECORD']] <> 1:
			item[layerdict['MAXPKT']] += 1
			item[layerdict['HEAD']].append(data)
			item[layerdict['LINK']].append(link)
			item[layerdict['IP']].append(ipdata)
			item[layerdict['TCP']].append(tcpdata)
			item[layerdict['DATA']].append(skip)
			if FLAG == 1:
				# 如果在该数据包中发现了我们想要的GET请求，则命中，后续会将缓存的数据包写入如期的文件
				item[layerdict['RECORD']] = 1
				file_out = open(name, "wb")
				# pcap的文件头在文件创建的时候写入
				file_out.write(datahdr)
				item[layerdict['FILE']] = file_out
		elif item[layerdict['RECORD']] == 1:
			file_out = item[layerdict['FILE']]	
			# 首先将缓存的数据包写入文件
			for index in range(cnt+1):
				file_out.write(item[layerdict['HEAD']][index])
				file_out.write(item[layerdict['LINK']][index])
				file_out.write(item[layerdict['IP']][index])
				file_out.write(item[layerdict['TCP']][index])
				file_out.write(item[layerdict['DATA']][index])
			item[layerdict['MAXPKT']] = -1
			
			# 然后写入当前的数据包
			file_out.write(data)
			file_out.write(link)
			file_out.write(ipdata)
			file_out.write(tcpdata)
			file_out.write(skip)
			
			
	else:
		item = [0, 0, [], [], [], [], [], 0, 0]
		# 该四元组第一次被扫描到，创建字典元素，并缓存这第一个收到的数据包到List
		item[layerdict['HEAD']].append(data)
		item[layerdict['LINK']].append(link)
		item[layerdict['IP']].append(ipdata)
		item[layerdict['TCP']].append(tcpdata)
		item[layerdict['DATA']].append(skip)
		files4out[name] = item

	# read next packet
	data = file.read(pkthdrlen)

file.close
for item in files4out.values():
	file_out = item[layerdict['FILE']]	
	if file_out <> 0:
		file_out.close()

