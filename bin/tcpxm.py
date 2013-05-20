#! /usr/bin/env python
# -*- coding: utf-8 -*-
#sudo ./tcpxm.py eth0 "port 80"
#ver: 1.0
#jingyuan@xiaomi.com

import sys
import pcap
import string
import time
import socket
import struct
import os
import re
import fcntl
import getopt
from Queue import Queue
from Queue import Full
import random  
import threading  
import time  
import logging

mylock = threading.RLock() 
tcp_flow = {}
store_queue = Queue(100000)
protocols = {socket.IPPROTO_TCP:'tcp',
             socket.IPPROTO_UDP:'udp',
             socket.IPPROTO_ICMP:'icmp'}
TCP_BIT = {'TH_FIN':0x01,
           'TH_SYN':0x02,
           'TH_RST':0x04,
           'TH_PUSH':0x08,
           'TH_ACK':0x10,
           'TH_URG':0x20}
MAX_HASH = 100000
TIME_LIMIT = 60
netdev = None
filter_str = None
backend_ip = None
DEBUG = False


def decode_ip_packet(s):
    d                        = {}
    d['version']             = (ord(s[0]) & 0xf0) >> 4
    d['header_len']          = ord(s[0]) & 0x0f
    d['tos']                 = ord(s[1])
    d['total_len']           = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']                  = socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']               = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']     = socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']                 = ord(s[8])
    d['protocol']            = ord(s[9])
    d['checksum']            = socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']      = pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4*(d['header_len']-5)]
    else:
        d['options'] = None
    d['data']             = s[4*d['header_len']:]
    d['source_port']      = socket.ntohs(struct.unpack('H',d['data'][0:2])[0])
    d['destination_port'] = socket.ntohs(struct.unpack('H',d['data'][2:4])[0])
    d['seq']              = socket.ntohl(struct.unpack('I',d['data'][4:8])[0])
    d['ack']              = socket.ntohl(struct.unpack('I',d['data'][8:12])[0])
    d['tcp_header_len']   = (ord(d['data'][12]) & 0xf0) >> 4
    d['tcp_bit']          = (ord(d['data'][13]) & 0x3f)
    d['tcp_data']         = d['data'][4*d['tcp_header_len']:]
    return d
        
def is_set(flag, val):
    return (flag & TCP_BIT[val])

def store_packet(pktlen, data, timestamp):
    if not data:
        return

    
    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        str_stoc = "%s %s %s %s" % (decoded['destination_address'], decoded['destination_port'], decoded['source_address'], decoded['source_port'])
        str_ctos = "%s %s %s %s" % (decoded['source_address'], decoded['source_port'], decoded['destination_address'], decoded['destination_port'])
        #T1: SYN and ACK means that the flow is a server -> client flow
        if is_set(decoded['tcp_bit'], 'TH_SYN') and is_set(decoded['tcp_bit'], 'TH_ACK'):
            #logging.debug("packet is handshake SYN/ACK")
            if tcp_flow.has_key(str_stoc) and tcp_flow[str_stoc]['seq']+1 == decoded['ack']:
                tcp_flow[str_stoc]['t1'] = timestamp 
                tcp_flow[str_stoc]['seq'] = decoded['seq']
                tcp_flow[str_stoc]['ack'] = decoded['ack']
                #print "<---------------T1--------------->"

        #T0: SYN means that the flow is a client -> server flow
        elif is_set(decoded['tcp_bit'], 'TH_SYN'):
            #logging.debug("packet is handshake SYN")
            if tcp_flow.has_key(str_ctos):
                logging.debug("%s is already exist!" % str_ctos)
            tcp_flow[str_ctos] = {}
            tcp_flow[str_ctos]['t0'] = timestamp
            tcp_flow[str_ctos]['ack'] = decoded['ack']
            tcp_flow[str_ctos]['seq'] = decoded['seq']
            #print "<---------------T0--------------->"



        elif is_set(decoded['tcp_bit'], 'TH_ACK') and not is_set(decoded['tcp_bit'], 'TH_SYN') and not is_set(decoded['tcp_bit'], 'TH_PUSH') and not is_set(decoded['tcp_bit'], 'TH_FIN'):
            #logging.debug("packet is handshake ACK, TCP 3 times handshake finished!")           
            tmp_str = "%s %s %s %s" % (decoded['source_address'], decoded['source_port'], decoded['destination_address'], decoded['destination_port'])
           
            if tcp_flow.has_key(str_ctos):
                #T2: ACK means that the flow is TCP 3 times handshake finished.
                if tcp_flow[str_ctos]['seq']+1 == decoded['ack']:
                    tcp_flow[str_ctos]['t2'] = timestamp
                    tcp_flow[str_ctos]['ack'] = decoded['ack']
                    tcp_flow[str_ctos]['seq'] = decoded['seq']
                    #print "<---------------T2--------------->"
               
               #client answer login success, send ack flow
                elif tcp_flow[str_ctos].has_key('succ_ack') and tcp_flow[str_ctos]['succ_ack'] == decoded['seq']:
                    tcp_flow[str_ctos]['t7'] = timestamp
                    try:
                        mylock.acquire()
                        ctos = tcp_flow.pop(str_ctos)
                        mylock.release()
                        for x in ['t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 'usr']:
                            if not ctos.has_key(x):
                                logging.debug("%s flow don't have %s" % (str_ctos, x))
                                return
                        rtt = int((ctos['t2'] - ctos['t1'])  * 1000 )
                        tmp_str = '%s %s %d %d %d %d %d %d %d %d' % (str_ctos,
                                                    str(ctos['usr']),
                                                    int((ctos['t6'] - ctos['t0']) * 1000 + rtt),
                                                    int((ctos['t1'] - ctos['t0']) * 1000),
                                                    rtt,
                                                    int((ctos['t3'] - ctos['t2']) * 1000),
                                                    int((ctos['t4'] - ctos['t3']) * 1000),
                                                    int((ctos['t5'] - ctos['t4']) * 1000),
                                                    int((ctos['t6'] - ctos['t5']) * 1000),
                                                    int((ctos['t7'] - ctos['t6']) * 1000)
                                                )
                        store_queue.put(tmp_str, True, 0.1)
                    except Full, e:
                        logging.warning("overflow store_queue!")
                    #print "<---------------T7--------------->"

            #T4: after client first send push flow, server answer ACK
            elif tcp_flow.has_key(str_stoc) and tcp_flow[str_stoc]['ack'] == decoded['seq']:
                tcp_flow[str_stoc]['t4'] = timestamp 
                tcp_flow[str_stoc]['seq'] = decoded['seq']
                tcp_flow[str_stoc]['ack'] = decoded['ack']
                #print "<---------------T4--------------->"


        #PUSH flow ,don't record seq and ack
        elif is_set(decoded['tcp_bit'], 'TH_PUSH'):
            #T3: after 3 times handshake, client first send push flow.
            if tcp_flow.has_key(str_ctos):
                if tcp_flow[str_ctos]['seq'] == decoded['seq']:
                    tcp_flow[str_ctos]['t3'] = timestamp
                    #print "<---------------T3--------------->"
              
                #get client miliao id, match usr=\"(\d+)\"
                if DEBUG:
                    p = re.search(ur"(Accept)", decoded['tcp_data'])
                else:
                    p = re.search(ur"usr=\"(\d+)\"", decoded['tcp_data'])
                if p:
                    tcp_flow[str_ctos]['usr'] = p.group(1)
                    #print "<------get user id---------------->"  

            #T5: server first send push flow, after server answer ACK
            elif tcp_flow.has_key(str_stoc):
                if tcp_flow[str_stoc]['seq'] == decoded['seq']:
                    tcp_flow[str_stoc]['t5'] = timestamp
                    #print "<---------------T5--------------->"
                   
                #T6: catch success flag that means user login finished. match <success/>
                if DEBUG:
                    p = re.search(ur"Content-Type", decoded['tcp_data'])
                else:
                    p = re.search(ur"<success/>", decoded['tcp_data'])
                if p:
                    tcp_flow[str_stoc]['t6'] = timestamp
                    tcp_flow[str_stoc]['succ_ack'] = decoded['ack']
                    #print "<---------------T6--------------->"
    

def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        print '\n%s.%f %s:%s > %s:%s' % (time.strftime('%H:%M', time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                decoded['source_port'],
                                decoded['destination_address'],
                                decoded['destination_port'])
        for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            print '    %s: %d' % (key, decoded[key])
        print '    protocol: %s' % protocols[decoded['protocol']]
        print '    header checksum: %d' % decoded['checksum']
        print '    seq: %s' % decoded['seq']
        print '    ack: %s' % decoded['ack']
        print '    tcp_header_len: %s' % decoded['tcp_header_len']
        print '    tcp_bit:',
        for k,v in TCP_BIT.items():
            if (decoded['tcp_bit'] & v):
                print "%s " % k,
        print '    tcp_data: %s' % decoded['tcp_data']


class Sniffer(threading.Thread):
    def __init__(self, t_name):
        threading.Thread.__init__(self, name = t_name)
        logging.info("Thread %s started!" % t_name)

    def run(self):
        try:
            p = pcap.pcapObject()
            dev = netdev
            net, mask = pcap.lookupnet(dev)
            p.open_live(dev, 1600, 0, 100)
            if backend_ip:
                p.setfilter(filter_str + " and not host " + backend_ip, 0, 0)
            else:
                p.setfilter(filter_str, 0, 0)
            logging.info("start to sniffy...")
            while True:
                p.dispatch(1, store_packet)
        except:
            print "something wrong, exit!"
            os.kill(os.getpid(), 9)

class Logger(threading.Thread):
    def __init__(self, t_name):
        threading.Thread.__init__(self, name = t_name)
        logging.info("Thread %s started!" % t_name)
    
    def run(self):
        while True:
            if not store_queue.empty():
                logging.info("%s" % store_queue.get())
            else:
                time.sleep(0.5)


class Cleaner(threading.Thread):
    def __init__(self, t_name):
        threading.Thread.__init__(self, name = t_name)
        logging.info("Thread %s started!" % t_name)

    def run(self):
        while True:
            tmp_time = time.time()
            if len(tcp_flow) > MAX_HASH: 
                mylock.acquire()
                for key in tcp_flow.keys():
                    if tcp_flow[key].has_key('t0') and int(tmp_time - tcp_flow[key]['t0']) > TIME_LIMIT:
                        del tcp_flow[key]
                mylock.release()
            else:
                for key in tcp_flow.keys():
                    #mylock.acquire()
                    if tcp_flow.has_key(key) and tcp_flow[key].has_key('t0'):
                        if int(tmp_time - tcp_flow[key]['t0']) > TIME_LIMIT:
                            mylock.acquire()
                            del tcp_flow[key]
                            mylock.release()

            time.sleep(1)

def help():
    print 'usage: tcpxm.py -i eth0 -f "port 80" -b 10.235.7.160'
    print '-i 网卡接口 eth0'
    print '-b 过滤后端源站IP'
    print '-f set filter(man 7 pcap-filter). examle: "port 80" '
    print '-D DEBUG'
    print 'jingyuan@xiaomi.com'

def main():
    s = Sniffer('sniffer')
    c = Cleaner('cleaner')
    l = Logger('logger')

    logging.info("init Thread")
    s.start()
    c.start()
    l.start()

    s.join()
    c.join()
    l.join()    
    logging.info("All threads terminate!")

if __name__ == '__main__':
    try:
        options, args = getopt.getopt(sys.argv[1:],"hdu:f:i:b:",["help", "DEBUG"])

    except getopt.GetoptError:
        help()
        sys.exit(1)

    for name, value in options:
        if name in ("-h", "--help"):
            help()
            sys.exit(1)
        if name in ("-i"):
            netdev = value
        if name in ("-f"):
            filter_str = value
        if name in ("-b"):
            backend_ip = value
        if name in ("-d"):
            DEBUG = True

    logging.basicConfig(level=logging.DEBUG,
                                    format='%(asctime)s  [%(levelname)s]  %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S',
                                    filename='../log/tcpxm.log',
                                    filemode='a')
    try: 
        pid = os.fork() 
        if pid > 0:
            # exit first parent
            sys.exit(0) 
    except OSError, e: 
        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1)

    # decouple from parent environment
    os.setsid() 
    os.umask(0) 

    # do second fork
    try: 
        pid = os.fork() 
        if pid > 0:
            # exit from second parent, print eventual PID before
            sys.exit(0)
    except OSError, e: 
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1) 

    #lock pid file for single instance
    fd = open('../conf/tcpxm.pid', 'w')
    if not fd:
        print >>sys.stderr, "read tcpxm.pid faild"
        sys.exit(0)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        #write pid file
        #fd.truncate()
        #fd.seek(0)
        pid = str(os.getpid())
        fd.write(pid)
        fd.flush()

    except IOError:
        # another instance is running
        print >>sys.stderr, "another instance is running"
        sys.exit(0)

    #run
    main()
