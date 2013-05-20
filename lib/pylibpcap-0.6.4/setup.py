#! /usr/bin/env python

# $Id: setup.py,v 1.17 2012/01/06 00:13:13 wiml Exp $

import sys
import distutils.command.build
from distutils.command.build_ext import build_ext
from distutils.command.clean import clean
from distutils.core import setup, Extension, Command

import os

config_defines = [ ]
### CONFIGURATION ###

# uncomment this line and comment out the next one if you want to build
# pcap.c from the SWIG interface
# sourcefiles = ["mk-constants.py", "pcap.i"]
sourcefiles = ["pcap.c"]

# if you are building against a non-installed version of libpcap,
# specify its directory here, otherwise set this to None
libpcap_dir = None
# libpcap_dir = "/home/wiml/netsrc/libpcap/libpcap-0.7.2"
# libpcap_dir = "/home/wiml/netsrc/libpcap/libpcap-0.8.3"
# libpcap_dir = "/home/wiml/netsrc/libpcap/cvs.tcpdump.org/libpcap"

include_dirs = [ ]

# Depending on what version of libpcap you're using, you may need to
# uncomment one of these lines.

# Versions prior to 0.8 don't have pcap_lib_version().
# config_defines.append('WITHOUT_PCAP_LIB_VERSION')

# Versions prior to 0.8 don't have pcap_breakloop().
# config_defines.append('WITHOUT_BREAKLOOP')

# Versions prior to 0.7.2 or so don't have pcap_list_datalinks().
# config_defines.append('WITHOUT_LIST_DATALINKS')

# Some versions don't have pcap_version[].
# config_defines.append('WITHOUT_VERSION_STRING')


### END OF CONFIGURATION ###
# You shouldn't need to modify anything below this point unless you're
# doing development

sourcefiles += ["pcap_interface.c","exception.c","error.c"]


# I modified build_ext to add -shadow to the swig line.
# yay!

class pcapclean(clean):
    other_derived = [ 'pcap.py', 'pcap.c', 'constants.c', 'MANIFEST' ] 
    def run (self):
        #if self.all:
        for derived in self.other_derived:
            if os.access(derived, os.F_OK):
                print derived
                self.announce('removing: %s' % derived)
                if not self.dry_run:
                    os.unlink(derived)
        clean.run (self)
#        self.run_command('make_clean')

class pcap_build_ext(build_ext):

    def before_swig_sources(self, sources):
        new_sources = [ ]
        for source in sources:
            if source == 'mk-constants.py':
                self.make_file( (source,), 'constants.c', execfile, (source,) )
            else:
                new_sources.append(source)
        return new_sources
      
    def swig_sources(self, sources, extension=None):
    
        """Walk the list of source files in 'sources', looking for SWIG
        interface (.i) files.  Run SWIG on all that are found, and
        return a modified 'sources' list with SWIG source files replaced
        by the generated C (or C++) files.
        """

        sources = self.before_swig_sources(sources)
    
        new_sources = []
        swig_sources = []
        swig_targets = {}
    
        # XXX this drops generated C/C++ files into the source tree, which
        # is fine for developers who want to distribute the generated
        # source -- but there should be an option to put SWIG output in
        # the temp dir.
    
        if self.swig_cpp:
            target_ext = '.cpp'
        else:
            target_ext = '.c'
    
        for source in sources:
            (base, ext) = os.path.splitext(source)
            if ext == ".i":             # SWIG interface file
                new_sources.append(base + target_ext)
                swig_sources.append(source)
                swig_targets[source] = new_sources[-1]
            else:
                new_sources.append(source)
    
        if not swig_sources:
            return new_sources
    
        swig = self.find_swig()
        swig_cmd = [swig, "-Wall", "-python", "-shadow", "-ISWIG"]
        if self.swig_cpp:
            swig_cmd.append("-c++")
    
        for source in swig_sources:
            target = swig_targets[source]
            self.announce("swigging %s to %s" % (source, target))
            self.spawn(swig_cmd + ["-o", target, source])

            self.announce('doc-ifying swig-generated source file %s' % target)
            self.spawn([sys.executable, './build-tools/docify.py', target])

            self.announce('doc-ifying swig-generated shadow class file %s' % 'pcap.py')
            self.spawn([sys.executable, './build-tools/docify-shadow.py', 'pcap.py'])
    
        return new_sources

    # swig_sources ()

    def find_swig(self):
        if os.environ.has_key('SWIG'):
            return os.environ['SWIG']
        return build_ext.find_swig(self)
#

class build_shadowed (distutils.command.build.build):
    # this moves the 'build_py' subcommand to the end, so it happens
    # after the pcap.py module has been created by the build_ext command
    sub_commands = distutils.command.build.build.sub_commands
    sub_commands  = filter(lambda x: x[0] != 'build_py', sub_commands) + \
                    filter(lambda x: x[0] == 'build_py', sub_commands)


defines = [ ('SWIG_COBJECT_TYPES', None) ] + \
          map(lambda x: (x, None), config_defines)

if libpcap_dir is None:
    pcap_extension = Extension("_pcapmodule",
                                sourcefiles,
                                include_dirs = include_dirs,
                                define_macros = defines,
                                libraries = [ "pcap" ]
                                )
else:
    include_dirs.append( libpcap_dir )
    # extension_objects=[ os.path.join(libpcap_dir, 'libpcap.a') ]
    pcap_extension = Extension("_pcapmodule",
                                sourcefiles,
                                include_dirs = include_dirs,
                                define_macros = defines,
                                library_dirs = [ libpcap_dir ],
                                libraries = [ "pcap" ]
                                )
#



setup (# Distribution meta-data
        name = "pylibpcap",
        version = "0.6.4",
        license = "BSD",
        description = 'pylibpcap is a python module for the libpcap packet capture library.',
        long_description = 'pylibpcap is a python module for the libpcap packet capture library.',
        url = "http://pylibpcap.sourceforge.net/",
        author = "David Margrave",
        author_email = "davidma@eskimo.com",
        maintainer = "Wim Lewis",
        maintainer_email = "wiml@users.sourceforge.net",
        # keywords = "",
        # platforms = "",
        py_modules = [ "pcap" ],
        ext_modules = [ pcap_extension ],
        cmdclass = {'clean': pcapclean,
                    'build_ext': pcap_build_ext,
                    'build': build_shadowed},
        classifiers = [ 'Development Status :: 4 - Beta',
                        'Intended Audience :: Developers',
                        'Intended Audience :: System Administrators',
                        'License :: OSI Approved :: BSD License',
                        'Programming Language :: C',
                        'Programming Language :: Python',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        'Topic :: System :: Networking :: Monitoring' ],
      )

# vim:set ts=4 sw=4 et:
