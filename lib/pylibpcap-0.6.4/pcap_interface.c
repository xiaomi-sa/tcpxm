
/*
Python libpcap
Copyright (C) 2001, David Margrave
Copyright (C) 2003-2004,2012 William Lewis
Based on PY-libpcap (C) 1998, Aaron L. Rhodes

This program is free software; you can redistribute it and/or
modify it under the terms of the BSD Licence. See the file COPYING
for details.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
*/


#include <Python.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pypcap.h"

#ifdef AF_LINK
#include <net/if_dl.h>
#endif

#if defined(AF_INET6) && !defined(INET6_ADDRSTRLEN)
#define INET6_ADDRSTRLEN 46
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#if 0
/* this was required with LBL libpcap but is evidently not required with
   or even present in the new libpcap that comes with RH 7.2
 */
void linux_restore_ifr(void);
#endif


static int check_ctx(pcapObject *self);
static int pcapObject_invoke(pcapObject *self, int cnt, PyObject *PyObj,
			     int (*f)(pcap_t *, int, pcap_handler, u_char *));
static
void PythonCallBack(u_char *user_data,
                    const struct pcap_pkthdr *header,
                    const u_char *packetdata);

struct pythonCallBackContext {
  PyObject *func;
  pcap_t *pcap;
  PyThreadState *threadstate;
};

static int check_ctx(pcapObject *self)
{
  if (!self->pcap) {
    PyErr_SetString(PyExc_RuntimeError,
                    "pcapObject must be initialized via open_live(), "
                    "open_offline(), or open_dead() methods");
    return 1;
  }
  return 0;
}

static int check_noctx(pcapObject *self)
{
  if (self->pcap) {
    PyErr_SetString(PyExc_RuntimeError, "pcapObject was already opened");
    return 1;
  }
  return 0;
}


/*
pcapObject *new_pcapObject(char *device, int snaplen, int promisc, int to_ms)
*/
pcapObject *new_pcapObject(void)
{
  pcapObject *self;

  self = (pcapObject *)malloc(sizeof(pcapObject));
  self->pcap = NULL;
  self->pcap_dumper=NULL;

  return self;
}

void delete_pcapObject(pcapObject *self)
{
  if (self->pcap_dumper)
    pcap_dump_close(self->pcap_dumper);
  if (self->pcap)
    pcap_close(self->pcap);
#if 0
#ifdef __linux
  linux_restore_ifr();
#endif
#endif

  free(self);
}

void pcapObject_open_live(pcapObject *self, char *device, int snaplen,
                          int promisc, int to_ms)
{
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *opened;

  if (check_noctx(self))
    return;

  Py_BEGIN_ALLOW_THREADS
  opened = pcap_open_live(device, snaplen, promisc, to_ms, ebuf);
  Py_END_ALLOW_THREADS

  if (!opened)
    throw_exception(-1, ebuf);
  else
    self->pcap = opened;
}

void pcapObject_open_dead(pcapObject *self, int linktype, int snaplen)
{
  pcap_t *opened;

  if (check_noctx(self))
    return;

  Py_BEGIN_ALLOW_THREADS
  opened = pcap_open_dead(linktype, snaplen);
  Py_END_ALLOW_THREADS

  if (!opened)
    throw_exception(errno, "pcap_open_dead failed");
  else
    self->pcap = opened;
}

void pcapObject_open_offline(pcapObject *self, char *fname)
{
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *opened;

  if (check_noctx(self))
    return;

  Py_BEGIN_ALLOW_THREADS
  opened = pcap_open_offline(fname, ebuf);
  Py_END_ALLOW_THREADS

  if (!opened)
    throw_exception(-1, ebuf);
  else
    self->pcap = opened;
}


void pcapObject_dump_open(pcapObject *self, char *fname)
{
  if (check_ctx(self))
    return;

  Py_BEGIN_ALLOW_THREADS
  if (self->pcap_dumper)
    pcap_dump_close(self->pcap_dumper);
  self->pcap_dumper = pcap_dump_open(self->pcap, fname);
  Py_END_ALLOW_THREADS

  if (!self->pcap_dumper)
    throw_pcap_exception(self->pcap, "pcap_dump_open");
}


void pcapObject_setnonblock(pcapObject *self, int nonblock)
{
  char ebuf[PCAP_ERRBUF_SIZE];

  if (check_ctx(self))
    return;
  if (pcap_setnonblock(self->pcap, nonblock, ebuf)<0)
    throw_pcap_exception(self->pcap, "pcap_setnonblock");
}

int pcapObject_getnonblock(pcapObject *self)
{
  int status;
  char ebuf[PCAP_ERRBUF_SIZE];

  if (check_ctx(self))
    return 0;
  status=pcap_getnonblock(self->pcap, ebuf);
  if (status<0)
    throw_exception(-1, ebuf);
  return status;
}

void pcapObject_setfilter(pcapObject *self, char *str,
                          int optimize, in_addr_t netmask)
{
  struct bpf_program bpfprog;
  int status;
  PyThreadState *saved_state;

  if (check_ctx(self))
    return;

  saved_state = PyEval_SaveThread(); /* Py_BEGIN_ALLOW_THREADS */

  status = pcap_compile(self->pcap, &bpfprog, str, optimize, (bpf_u_int32)netmask);
  if (status) {
    PyEval_RestoreThread(saved_state);
    throw_pcap_exception(self->pcap, "pcap_compile");
    return;
  }

  status = pcap_setfilter(self->pcap, &bpfprog);
  PyEval_RestoreThread(saved_state);
  if (status) 
    throw_pcap_exception(self->pcap, "pcap_setfilter");
}


void pcapObject_loop(pcapObject *self, int cnt, PyObject *PyObj)
{
  pcapObject_invoke(self, cnt, PyObj, pcap_loop);
}

int pcapObject_dispatch(pcapObject *self, int cnt, PyObject *PyObj)
{
  return pcapObject_invoke(self, cnt, PyObj, pcap_dispatch);
}

static
int pcapObject_invoke(pcapObject *self, int cnt, PyObject *PyObj,
		      int (*f)(pcap_t *, int, pcap_handler, u_char *))
{
  int status;
  pcap_handler callback;
  void *callback_arg;
  struct pythonCallBackContext callbackContextBuf;

  if (check_ctx(self))
    return -1;

  if (PyCallable_Check(PyObj)) {
    callback = PythonCallBack;
    callbackContextBuf.func = PyObj;
    callbackContextBuf.pcap = self->pcap;
    callback_arg = &callbackContextBuf;
  } else if(PyObj == Py_None && self->pcap_dumper != NULL) {
    callback = pcap_dump;
    callback_arg = self->pcap_dumper;
  } else {
      PyErr_SetString(PyExc_TypeError,
                      "argument must be a callable object, or None to invoke dumper");
    return -1;
  }

  /* Release the GIL and store the current thread state. We store it in the
     callbackContextBuf even if we're not otherwise using that buf (the
     pcap_dump callback doesn't touch Python so it doesn't need to reacquire
     the GIL). */
  callbackContextBuf.threadstate = PyEval_SaveThread();

  status=(*f)(self->pcap, cnt, callback, callback_arg);

  PyEval_RestoreThread(callbackContextBuf.threadstate);

  /* the pcap(3) man page describes the specal return values -1 and -2 */
  if (status == -2 && PyErr_Occurred()) {
    /* pcap_breakloop() was called */
    return status;
  }
  if (status<0) {
      throw_pcap_exception(self->pcap, NULL);
    return status;
  }
  if (PyErr_CheckSignals())
    return -1;
  return status;
}

PyObject *pcapObject_next(pcapObject *self)
{
  struct pcap_pkthdr header;
  const unsigned char *buf;
  PyObject *outObject;

  if (check_ctx(self))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  buf = pcap_next(self->pcap, &header);
  Py_END_ALLOW_THREADS

  if (buf == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }

  outObject = Py_BuildValue("is#f", header.len, buf, header.caplen,
			    header.ts.tv_sec*1.0+header.ts.tv_usec*1.0/1e6);
  return outObject;

}

int pcapObject_datalink(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_datalink(self->pcap);
}

#ifndef WITHOUT_LIST_DATALINKS
PyObject *pcapObject_datalinks(pcapObject *self)
{
  int *links;
  int linkcount, i;
  PyObject *result;

  if (check_ctx(self))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  links = NULL;
  linkcount = pcap_list_datalinks(self->pcap, &links);
  Py_END_ALLOW_THREADS
  if (linkcount < 0) {
    throw_pcap_exception(self->pcap, "list_datalinks");
    return NULL;
  }

  result = PyTuple_New(linkcount);
  if (!result) {
    free(links);
    return NULL;
  }
  for(i = 0; i < linkcount; i ++) {
    PyObject *linktype = PyInt_FromLong( (long) (links[i]) );
    if (!linktype) {
      Py_DECREF(result);
      free(links);
      return NULL;
    }
    PyTuple_SET_ITEM(result, i, linktype);  /* consumes a reference to linktype */
  }
  free(links);
  return result;
}
#endif /* WITHOUT_LIST_DATALINKS */

int pcapObject_snapshot(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_snapshot(self->pcap);
}


int pcapObject_is_swapped(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_is_swapped(self->pcap);
}


int pcapObject_major_version(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_major_version(self->pcap);
}


int pcapObject_minor_version(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_minor_version(self->pcap);
}


PyObject *pcapObject_stats(pcapObject *self)
{
  struct pcap_stat pstat;
  PyObject *outTuple;

  if (check_ctx(self))
    return NULL;

  Py_BEGIN_ALLOW_THREADS

  pstat.ps_recv = 0;
  pstat.ps_drop = 0;
  pstat.ps_ifdrop = 0;

  /* pcap_stats always returns 0, no need to check */
  pcap_stats(self->pcap, &pstat);

  Py_END_ALLOW_THREADS

  outTuple = Py_BuildValue("(iii)", 
			   pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop);

  return outTuple;
}

FILE *pcapObject_file(pcapObject *self)
{

  if (check_ctx(self))
    return NULL;

  return pcap_file(self->pcap);
  
}



int pcapObject_fileno(pcapObject *self)
{
  if (check_ctx(self))
    return 0;

  return pcap_fileno(self->pcap);
}





/* functions that are not methods of pcapObject */

char *lookupdev(void)
{
  char *dev;
  char ebuf[PCAP_ERRBUF_SIZE];

  Py_BEGIN_ALLOW_THREADS
  dev = pcap_lookupdev(ebuf);
  Py_END_ALLOW_THREADS
  
  if (dev)
    return dev;
  else {
    throw_exception(errno,ebuf);
    return NULL;
  }

}

#ifdef AF_LINK

static PyObject *
string_from_sockaddr_dl(struct sockaddr_dl *sdl)
{
  char *buf;
  int sdl_len, dlpos, buf_size;
  PyObject *str;
  
  sdl_len = sdl->sdl_alen + sdl->sdl_slen;

  if (sdl_len == 0) {
    Py_INCREF(Py_None);
    return(Py_None);
  }

  buf_size = 3 * sdl_len;
  buf = malloc(buf_size);
  
  for(dlpos = 0; dlpos < sdl_len; dlpos ++) {
    char *bufpos = buf + (3 * dlpos);
    unsigned char dlbyte = sdl->sdl_data[sdl->sdl_nlen + dlpos];
    
    sprintf(bufpos, "%02x", dlbyte);
    if (dlpos == sdl_len - 1)
      bufpos[2] = (char)0;
    else if (dlpos == sdl->sdl_alen - 1)
      bufpos[2] = '#';
    else
      bufpos[2] = ':';
  }
  
  str = PyString_FromString(buf);
  free(buf);
  return str;
}

#endif /* AF_LINK */

/* Ways to figure out how long a given sockaddr is. This varies
   a lot from system to system. Fortunately, we have access to
   Python's autoconf defined from pyconfig.h. */

#if defined(HAVE_SOCKADDR_SA_LEN)
#define SOCKADDR_LENGTH(sa) ((sa)->sa_len)
#elif defined(SA_LEN)
#define SOCKADDR_LENGTH(sa) (SA_LEN(sa))
#else
#define SOCKADDR_LENGTH(sa) sockaddr_length(sa)
static int sockaddr_length(struct sockaddr *sa)
{
  switch(sa->sa_family) {
  case AF_INET:
    return sizeof(struct sockaddr_in);
    break;
#ifdef AF_INET6
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
    break;
#endif
#ifdef AF_LINK
  case AF_LINK:
    return sizeof(struct sockaddr_dl);
    break;
#endif
  default:
#ifdef HAVE_SOCKADDR_STORAGE
    return sizeof(struct sockaddr_storage);
#else
    return sizeof(struct sockaddr);
#endif
    break;
  }
}
#endif



PyObject *packed_sockaddr(struct sockaddr *sa)
{
  int length;

  if (sa == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  
  length = SOCKADDR_LENGTH(sa);
  return PyString_FromStringAndSize( (const char *)sa, length );
}

PyObject *object_from_sockaddr(struct sockaddr *sa)
{
  char *buf;
  size_t buf_size;
  void *src;
  PyObject *result;
  
  if (sa == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  
  switch(sa->sa_family) {
  case AF_INET:
    src = &(((struct sockaddr_in *)sa) -> sin_addr);
    buf_size = INET_ADDRSTRLEN;
    break;
#ifdef AF_INET6
  case AF_INET6:
    src = &(((struct sockaddr_in6 *)sa) -> sin6_addr);
    buf_size = INET6_ADDRSTRLEN;
    break;
#endif
#ifdef AF_LINK
  case AF_LINK:
    result = string_from_sockaddr_dl( (struct sockaddr_dl *)sa );
    return result;
    break;
#endif
  default:
    /*
    PyErr_Format(PyExc_Exception, "unsupported address family %d", sa->sa_family);
    return NULL;
    */
    return PyString_FromFormat("<AF %d>", sa->sa_family);
  case AF_UNSPEC:
    Py_INCREF(Py_None);
    return Py_None;
  }
  
  buf = malloc(buf_size);
  if (inet_ntop(sa->sa_family, src, buf, buf_size) == NULL) {
      free(buf);
      throw_exception(errno, "cannot convert address to string");
      return NULL;
  }
  
  result = PyString_FromString(buf);
  free(buf);
  
  return result;
}

static
struct sockaddr *fill_netmask(struct sockaddr *ref, struct sockaddr *sa, void **free_this)
{
  if (ref == NULL || sa == NULL)
    return NULL;

#ifdef HAVE_SOCKADDR_SA_LEN
  if (ref->sa_len == 0)
    return NULL;

  if (sa->sa_family == AF_UNSPEC) {
    int len = MAX(sa->sa_len, ref->sa_len);
    struct sockaddr *buf;
    char *sap, *bufp;
    int offs;

    buf = *free_this = malloc(len);
    bufp = (char *)buf;
    sap = (char *)sa;
    offs = ( (char *)&(buf->sa_data) ) - ( (char *)buf );
    bcopy(ref, buf, offs);
    while( offs < len ) {
      bufp[offs] = ( offs < sa->sa_len )? sap[offs] : 0;
      offs ++;
    }

    return buf;
  }
#else
  if (sa->sa_family == AF_UNSPEC)
    return NULL;
#endif

  return sa;
}

PyObject *findalldevs(int unpack)
{
  pcap_if_t *if_head, *if_current;
  pcap_addr_t *addr_current;
  PyObject *out, *addrlist, *addrlist2, *tmp;
  int status;
  char ebuf[PCAP_ERRBUF_SIZE];
  PyObject *(*formatter)(struct sockaddr *);

  Py_BEGIN_ALLOW_THREADS
  status = pcap_findalldevs(&if_head, ebuf);
  Py_END_ALLOW_THREADS

  if (status) {
    throw_exception(errno, ebuf);
    pcap_freealldevs(if_head);
    return NULL;
  }

  if (unpack)
    formatter = object_from_sockaddr;
  else
    formatter = packed_sockaddr;

  out = PyList_New(0);
  for (if_current = if_head; if_current; if_current = if_current->next) {
    addrlist = PyList_New(0);

    for (addr_current = if_current->addresses; addr_current;
	   addr_current = addr_current->next) {
      struct sockaddr *filled_mask;
      void *tmp = NULL;

      filled_mask = fill_netmask(addr_current->addr, addr_current->netmask, &tmp);
      addrlist2 = Py_BuildValue("(O&O&O&O&)",
				 formatter, addr_current->addr, 
				 formatter, filled_mask,
				 formatter, addr_current->broadaddr, 
				 formatter, addr_current->dstaddr);

      if (tmp != NULL)
	free(tmp);

      if (addrlist2 == NULL) {
	Py_DECREF(addrlist);
	Py_DECREF(out);
	pcap_freealldevs(if_head);
	return NULL;
      }

      PyList_Append(addrlist, addrlist2);

      Py_DECREF(addrlist2);
    }

    tmp = Py_BuildValue("ssNi", 
			 if_current->name,
			 if_current->description,
			 addrlist,  /* refcount consumed by 'N' format */
			 if_current->flags);

    PyList_Append(out, tmp);
    Py_DECREF(tmp);
  }
  
  pcap_freealldevs(if_head);

  return out;
}

/* warning:  the libpcap that ships with RH 6.2 seems to have a buggy
   pcap_lookupnet */

PyObject *lookupnet(char *device)
{
  bpf_u_int32 net=0, mask=0;
  int status;
  char ebuf[PCAP_ERRBUF_SIZE];

  Py_BEGIN_ALLOW_THREADS
  status = pcap_lookupnet(device, &net, &mask, ebuf);
  Py_END_ALLOW_THREADS

  if (status) {
    throw_exception(errno, ebuf);
    return NULL;
  }

  return Py_BuildValue("ii", net, mask);
}

PyObject *aton(char *cp)
{
  PyObject *out;
  struct in_addr addr;
  int status;

  status=inet_aton(cp, &addr);
  if (!status) {
    throw_exception(errno, "inet_aton()");
    return NULL;
  }
  out=PyInt_FromLong(addr.s_addr);
  return out;
}

char *ntoa(in_addr_t addr)
{
  struct in_addr in;
  in.s_addr=addr;
  return inet_ntoa(in);  
}

/*
 * This function matches the prototype of a libpcap callback function.
 * It is passed as the function callback for libpcap.
 */

static
void PythonCallBack(u_char *user_data,
                    const struct pcap_pkthdr *header, 
                    const u_char *packetdata)
{
  struct pythonCallBackContext *context;
  PyObject *arglist, *result;

  context = (struct pythonCallBackContext *)user_data;

  /* Re-acquire the GIL and restore the Python thread state */
  PyEval_RestoreThread(context->threadstate);

  arglist = Py_BuildValue("is#f", header->len, packetdata, header->caplen,
			  header->ts.tv_sec*1.0+header->ts.tv_usec*1.0e-6);
  result = PyObject_CallObject(context->func, arglist);
  Py_DECREF(arglist);
  if (result == NULL) {
    /* An exception was raised by the Python callback */
    context->threadstate = PyEval_SaveThread();
#ifndef WITHOUT_BREAKLOOP
    pcap_breakloop(context->pcap);
#else
    /* Unfortunately, there's nothing much we can do here. */
#endif
    return;
  } else {
    /* ignore result (probably None) */
    Py_DECREF(result);
    context->threadstate = PyEval_SaveThread();
    return;
  }
}

