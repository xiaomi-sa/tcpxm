
/*
Python libpcap
Copyright (C) 2001, David Margrave
Copyright (C) 2004, William Lewis
Based PY-libpcap (C) 1998, Aaron L. Rhodes

This program is free software; you can redistribute it and/or
modify it under the terms of the BSD Licence. See the file COPYING
for details.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
*/

#include <stdlib.h>
#include <pcap.h>
#include <Python.h>
#include "pypcap.h"

void throw_exception(int err, char *ebuf)
{
  if (err == -1) {
    PyErr_SetString(PyExc_Exception, ebuf);
  } else {
    PyErr_Format(PyExc_Exception, "[Error %d] %s", err, ebuf);
  }
}

void throw_pcap_exception(pcap_t *pcap, char *fname)
{
  PyObject *errorArgs;
  
  if (fname == NULL)
    errorArgs = Py_BuildValue("(s)", pcap_geterr(pcap));
  else
    errorArgs = Py_BuildValue("(ss)", pcap_geterr(pcap), fname);
  PyErr_SetObject(pcapError, errorArgs);
  Py_DECREF(errorArgs);
}


