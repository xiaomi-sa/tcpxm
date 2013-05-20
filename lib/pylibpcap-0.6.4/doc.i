
#define pcap_doc \
"pcap module\n" \
"-----------\n" \
"pcapObject(): Returns a pcapObject instance, with the following methods.\n"\
"Please see the __doc__ attributes of the instance methods of a pcapObject\n"\
"for more information. (there are no method __doc__ attributes in the\n"\
"class). Also please note that at this time, method __doc__ attributes are\n"\
"only functional for python2.\n"\
"  open_live(device, snaplen, promisc, to_ms)\n" \
"  open_dead(linktype, snaplen)\n" \
"  open_offline(filename)\n" \
"  dump_open(filename)\n" \
"  setnonblock(nonblock)\n" \
"  getnonblock()\n" \
"  setfilter(filter, optimize, netmask)\n" \
"  loop(count, callback)\n" \
"  dispatch(count, callback)\n" \
"  next()\n" \
"  datalink()\n" \
"  snapshot()\n" \
"  is_swapped()\n" \
"  major_version()\n" \
"  stats()\n" \
"  fileno()\n\n"\
"Please see the __doc__ attributes of the following pcap module functions\n"\
"for further information:\n" \
"  lookupdev()\n" \
"  lookupnet(device)\n" \
"  findalldevs()\n" \
"  aton(addr)\n" \
"  ntoa(addr)\n" 

#define pcapObject_open_live_doc \
"open_live(device, snaplen, promisc, to_ms)\n\n" \
"Opens the interface specificed by 'device' for packet capture. 'snaplen'\n"\
"is the maximum number of bytes to capture per packet, 'promisc' indicates\n"\
"whether promiscuous mode should be used, and 'to_ms' specifies the read\n"\
"timeout in milliseconds."

#define pcapObject_open_dead_doc \
"open_dead(linktype, snaplen)\n\n" \
"open_dead is used to initialize the pcapObject so that methods that\n"\
"require the object to be initialized can be called, such as for compiling\n"\
"BPF code.  'snaplen' is the maximum number of bytes to capture per packet."


#define pcapObject_open_offline_doc \
"open_offline(filename)\n\n" \
"Opens a saved pcap/tcpdump-format file for reading. 'filename' is the name\n"\
"of the file to open.  The filename '-' is synonymous with stdin"


#define pcapObject_dump_open_doc \
"dump_open(filename)\n\n" \
"Opens a saved pcap/tcpdump-format file for writing. 'filename' is the name\n"\
"of the file to open.  The filename '-' is synonymous with stdout"



#define pcapObject_setnonblock_doc \
"setnonblock(nonblock)\n\n" \
"Puts the pcapObject in non-blocking mode ('nonblock'==1) or blocking mode\n"\
"('nonblock'==0).  Non-blocking behavior is only applicable to the\n"\
"dispatch method, and not the loop and next methods.  It has no effect on\n"\
"savefiles."


#define pcapObject_getnonblock_doc \
"getnonblock()\n\n" \
"Returns the non-blocking status of the pcapObject (returns 1 for\n"\
"non-blocking, returns 0 for blocking).  0 is always returned for savefiles\n"\
"Non-blocking behavior is only applicable to the dispatch method, and not\n"\
"the loop and next methods.  It has no effect on savefiles."


#define pcapObject_setfilter_doc \
"setfilter(filter, optimize, netmask)\n\n" \
"Applies a filtering rule to the pcapObject.  'filter' is a BPF-style \n"\
"filter expression, 'optimize' controls whether the compiled BPF code is \n"\
"optimized, and 'netmask' in a network byte-order integer specifying the \n"\
"netmask of the local network."


#define pcapObject_loop_doc \
"loop(count, callback)\n\n" \
"Read packets until 'count' packets have been received or an exception\n"\
"occurs.  The 'callback' argument is a python function of the form\n"\
"callback(pktlen, data, timestamp).  'pktlen' is the integer length of the\n"\
"observed packet on the wire, data is a string containing the captured\n"\
"bytes (may be less than the pktlen bytes), and the timestamp."


#define pcapObject_dispatch_doc \
"dispatch(count, callback)\n\n" \
"Read packets until at most 'count' packets have been read, or a timeout"\
"occurs, or an exception is raised.  Timeout behavior is not supported on\n"\
"all platforms, and on some platforms, the timer doesn't start until at least\n"\
"one packet arrives.  \n"\
"The 'callback' argument is a python function of the form\n"\
"callback(pktlen, data, timestamp).  'pktlen' is the integer length of the\n"\
"observed packet on the wire, data is a string containing the captured\n"\
"bytes (may be less than the pktlen bytes), and the timestamp."


#define pcapObject_next_doc \
"next()\n\n" \
"Reads the next packet from the interface, returning a tuple containing\n"\
"the integer length of the observed packet on the wire, a string containing\n"\
"the captured bytes (may be less than the pktlen bytes), and the timestamp."


#define pcapObject_datalink_doc \
"datalink()\n\n" \
"Returns an integer value representing the link layer type (e.g. DLT_EN10MB)"

#define pcapObject_datalinks_doc \
"datalinks()\n\n" \
"Returns a tuple of integer values representing the link layer types\n"\
"available on this interface (e.g. DLT_EN10MB)"

#define pcapObject_snapshot_doc \
"snapshot()\n\n" \
"Returns the snapshot length specified when open_live was called"

#define pcapObject_is_swapped_doc \
"is_swapped()\n\n" \
"Returns true if the current savefile uses a different byte order than the\n"\
"current system"

#define pcapObject_major_version_doc \
"major_version()\n\n" \
"returns the major number of the version of the pcap used to write the savefile.\n"

#define pcapObject_minor_version_doc \
"minor_version()\n\n" \
"returns the minor number of the version of the pcap used to write the savefile.\n"

#define pcapObject_stats_doc \
"stats()\n\n" \
"Returns a tuple containing number of packets received, number of packets\n"\
"dropped, and number of packets dropped by the interface.  This method is\n"\
"not applicable for savefiles"


#define pcapObject_fileno_doc \
"fileno()\n\n"\
"Returns the file descriptor number from which captured packets are read,\n"\
"if a network device was opened with open_live(), or -1, if a savefile was\n"\
"opened with pcap_open_offline()."

#define lookupdev_doc \
"lookupdev()\n\n" \
"Returns a string containing the name of an interface suitable for use\n" \
"with pcapObject.open_live and lookupnet.\n" 

#define lookupnet_doc \
"lookupnet(interface)\n\n" \
"Returns a tuple containing the network number and mask associated with\n" \
"the network device 'interface' in network byte order.\n"

#define findalldevs_doc \
"findalldevs()\n\n" \
"Returns a list of tuples for each device that can be opened with\n" \
"open_live(). Each tuple contains the following members:\n" \
"  name\n" \
"  description\n" \
"  addressess: a tuple of tuples for each address, containing the address,\n" \
"    netmask, broadcast address, and point-to-point address.\n" \
"  flags: PCAP_IF_LOOPBACK if a loopback interface\n"
