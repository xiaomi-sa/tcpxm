#!/usr/bin/env python
# This adds __doc__ lines to methods in swig-generated .py code.
# simple script to hack together python __doc__ support in swig-generated
# .py shadow class source files

import sys
import string
import re
import os



if len(sys.argv)<2:
    print 'usage: docify.py <swig-generated .py shadow class file>'
    sys.exit(1)

f=open(sys.argv[1],'r')
outfile=open('%s.tmp' % sys.argv[1],'w')

data=f.readlines()
#############################################################################
#for i in xrange(0,len(data)):
#    match=re.search('^.*def __del__',data[i])
#    if match:
#        #print match.group(0)
#        i=i+1
#        break
#
#if not match:
#    # One more chance to find __del__...
#    # This may be a more recent version of SWIG.
#    # Older versions generated __del__ methods.
#    # Newer versions appear to assign a lambda to __del__.
#    for i in xrange(0,len(data)):
#        match=re.search('^\s*__del__\s*=\s*lambda',data[i])
#        if match:
#            #print match.group(0)
#            i=i+1
#            break
#    if not match:
#        raise 'source file does not look like swigged shadow class code: '+sys.argv[1]
#
## read ahead to next def statement
#for i in xrange (i,len(data)):
#    if re.search('^\s*def', data[i]):
#        break
#
#pymeths=[]
#for i in xrange (i,len(data)):
#    if re.search('^\s*def __repr__', data[i]):
#        break
#    pymeths.append(data[i])
#
# I think that the above code can be replaced with the following and it will work
# on both old-style and new-style SWIG.

# collect all the lines that have public method names.
pymeths=[]
for i in xrange (0,len(data)):
    #if re.search('^\s*def\s+[^(]*', data[i]) and not re.search('^\s*def __repr__', data[i]) and not re.search('.*__del__.*', data[i]):
    if re.search('^\s*def\s+[^(]*', data[i]) and not re.search('^\s*def __.*', data[i]):
        pymeths.append(data[i])
#############################################################################

# Make a dictionary of all the method names from the method lines.
methods={}
for line in pymeths:
    methmatch=re.search('def +([^ (]*) *\(\*args\)',line)
    fnmatch=re.search('\:.*[^_p](_?pcapc?\.[^(, ]+) *[(,]',line)
    methode=None
    fname=None
    if methmatch: methode=methmatch.group(1)
    if fnmatch: fname=fnmatch.group(1)
    if methode and fname:
        methods[methode]=fname
    else:
        # print 'warning: method(%s) fname(%s)\n\tline: %s' % ( methode, fname, line )
        pass

#print methods

# delete "_doc = _pcap" lines from global scope
# (they get moved in slightly different form to inside __init__ method).
for i in xrange(0,len(data)):
    # write out everything that is NOT a "_doc = _pcap" line.
    if not re.search('^[^ ]+_doc = _pcap.[^ ]+_doc$',data[i]):
        outfile.write(data[i])
    match=re.search('^\s*def __init__',data[i])
    if match:
        #print match.group(0)
        i=i+1
        break
# spit out the next 2 lines verbatim
#outfile.write(data[i])
#i=i+1
#outfile.write(data[i])
#i=i+1

# put doc assignments inside of the __init__
outfile.write('        import sys\n')
outfile.write('        if int(sys.version[0])>=\'2\':\n')
for method, fname in methods.items():
    outfile.write('            self.%s.im_func.__doc__ = %s.__doc__\n' % (method, fname))


# spit out rest of file verbatim
for i in xrange (i,len(data)):
    outfile.write(data[i])

outfile.close()
f.close()

os.system('mv %s.tmp %s' % (sys.argv[1], sys.argv[1]))
# vim:set ts=4 sw=4 et:
