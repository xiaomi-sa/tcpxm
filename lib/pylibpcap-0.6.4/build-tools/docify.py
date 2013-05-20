#!/usr/bin/env python

# simple script to hack together python __doc__ support in swig-generated
# C source files

import sys
import string
import re
import os

if len(sys.argv)<2:
    print 'usage: docify.py <swig-generated .c wrapper file>'
    sys.exit(1)

f=open(sys.argv[1],'r')
outfile=open('%s.tmp' % sys.argv[1],'w')

data=f.readlines()

for i in xrange(0,len(data)):
    outfile.write(data[i])
    match=re.search('^static PyMethodDef SwigMethods',data[i])
    if match:
        #print match.group(0)
        break

if not match:
    raise 'source file does not look like swigged code: ' + argv[1]

pymeths=[]
for i in xrange (i,len(data)):
    if re.search('^.*\{.*NULL.*NULL.*\}', data[i]):
        break
    pymeths.append(data[i])

for line in pymeths:
    match=re.search('^.*char \*.*\".*\"',line)
    if match:
        fname=re.search('\".*\"',match.group(0)).group(0)[1:-1]
        if re.search('swigregister',fname):
      #      print 'skipping doc string for %s\n' % fname
            outfile.write(line)
            continue
   #      print fname
        outfile.write('\t{ (char *)\"%s\", _wrap_%s, METH_VARARGS, _doc_%s },\n' % 
                      (fname, fname, fname))

for i in xrange (i,len(data)):
    outfile.write(data[i])

outfile.close()
f.close()

os.system('mv %s.tmp %s' % (sys.argv[1], sys.argv[1]))
# vim:set ts=4 sw=4 et:
