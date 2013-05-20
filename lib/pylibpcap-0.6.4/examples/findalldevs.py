#! /usr/bin/env python

import pcap

def test_findalldevs():
    print pcap.findalldevs()
    for name, descr, addrs, flags in pcap.findalldevs():
        print 'Interface name: %s' % name
        print '   Description: %s ' % descr
        if addrs:
            i=1
            for ( addr, netmask, broadaddr, dstaddr) in addrs:
                print '    Address %d: %s ' % (i, addr)
                print '       Netmask: %s' % netmask
                print '     Broadcast: %s' % broadaddr
                print 'Peer dest addr: %s' % dstaddr
                i=i+1
        else:
            print ' No addresses'
        print ' flags: %s ' % flags

if __name__=="__main__":
    test_findalldevs()

# vim:set ts=4 sw=4 et:
