
/*
 * $Id: pypcap.h,v 1.13 2007/02/14 07:03:28 wiml Exp $
 * Python libpcap
 * Copyright (C) 2001,2002 David Margrave
 * Copyright (C) 2004 William Lewis
 * Based PY-libpcap (C) 1998, Aaron L. Rhodes
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the BSD Licence. See the file COPYING
 * for details.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 */

#include <pcap.h>
#include <sys/types.h>
#include <netinet/in.h>

/* the pcap class */
typedef struct {
  pcap_t *pcap;
  pcap_dumper_t *pcap_dumper;
} pcapObject;


/* pcapObject methods */
/*
pcapObject *new_pcapObject(char *device, int snaplen, int promisc, int to_ms);
*/
pcapObject *new_pcapObject(void);
void delete_pcapObject(pcapObject *self);
void pcapObject_open_live(pcapObject *self, char *device, int snaplen,
                          int promisc, int to_ms);
void pcapObject_open_dead(pcapObject *self, int linktype, int snaplen);
void pcapObject_open_offline(pcapObject *self, char *fname);
void pcapObject_dump_open(pcapObject *self, char *fname);
void pcapObject_setnonblock(pcapObject *self, int nonblock);
int pcapObject_getnonblock(pcapObject *self);
void pcapObject_setfilter(pcapObject *self, char *str,
                          int optimize, in_addr_t netmask);
PyObject *pcapObject_next(pcapObject *self);
int pcapObject_dispatch(pcapObject *self, int cnt, PyObject *PyObj);
void pcapObject_loop(pcapObject *self, int cnt, PyObject *PyObj);
int pcapObject_datalink(pcapObject *self);
PyObject *pcapObject_datalinks(pcapObject *self);
int pcapObject_snapshot(pcapObject *self);
int pcapObject_is_swapped(pcapObject *self);
int pcapObject_major_version(pcapObject *self);
int pcapObject_minor_version(pcapObject *self);
PyObject *pcapObject_stats(pcapObject *self);
FILE *pcapObject_file(pcapObject *self);
int pcapObject_fileno(pcapObject *self);



/* functions that are not methods of pcapObject */
PyObject *findalldevs(int unpack);
char *lookupdev(void);
PyObject *lookupnet(char *device);

/* useful non-pcap functions */
PyObject *aton(char *cp);
char *ntoa(in_addr_t addr);

/* error support fuctions */
extern PyObject *pcapError;
void init_errors(PyObject *module);
void throw_exception(int err, char *ebuf);
void throw_pcap_exception(pcap_t *pcap, char *fname);

