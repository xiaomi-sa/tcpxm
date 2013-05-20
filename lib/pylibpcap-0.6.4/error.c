
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

#include <pcap.h>
#include <Python.h>

/* static */ PyObject *pcapError;
static PyObject *error_object;

void init_errors(PyObject *m)
{
  const char *modname;
  char *namebuf;
  PyObject *d;

  d = PyModule_GetDict(m);
  modname = PyModule_GetName(m);
  namebuf = malloc(strlen(modname) + 11  /* ".EXCEPTION" + NUL */ );

  /* the base class */
  sprintf(namebuf, "%s.error", modname);
  pcapError = PyErr_NewException(namebuf, NULL, NULL);
  PyDict_SetItemString(d, "error", pcapError);

  sprintf(namebuf, "%s.EXCEPTION", modname);
  error_object = PyErr_NewException(namebuf,pcapError,NULL);
  PyDict_SetItemString(d, "EXCEPTION", error_object);
  Py_DECREF(error_object);

  free(namebuf);
  return;
} 

