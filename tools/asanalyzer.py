# https://gist.github.com/bitrot-sh/5acbc7c154f0fc7cf2b8c02d41d5be41

#!/usr/bin/env python3
"""
Usage: ./asanalyzer.py -d 5 '/home/user/asan_logs/*.log'

Analyze multiple ASan report logs and classify them based on backtrace logs.
ASLR should be disabled prior to running test cases.

Default stack trace depth is 5. This can be changed by passing -d or --depth.
"""

from sys import exit
from glob import glob
from optparse import OptionParser

DEBUG_ON = False

def DEBUG(msg):
    if DEBUG_ON:
        print(msg)

class AsanLog:
    """Asan log parsing class.
    Parameters:
        data - (String) of data from asan log
        fname - (String) Filename associated with the data
        depth - (Int) stack trace depth
    """
    def __init__(self, data=None, fname=None, depth=5):
        self.data  = data
        self.depth = depth
        self.fname = fname
        self.stack = []
        self.dups  = []
        self.desc  = ""
        if self.data:
            self.get_description()
            self.get_stack_trace()

    def get_description(self):
        if not self.data:
            return ""
        data = self.data.splitlines()
        for line in data:
            if "ERROR:" in line:
                self.desc = line[line.find('Sanitizer:')+11:]
                break
        return self.desc

    def get_stack_trace(self):
        """Return a list of stack trace addresses"""
        if not self.data:
            return []

        if not self.has_stack_trace():
            self.desc = "No ASAN Stack"
            return []

        data = self.data.splitlines()
        while "#0" not in data[0]:
            data.pop(0)
        for x in range(0, self.depth):
            lno = "#%d" % x
            if lno not in data[0]:
                return self.stack
            addr = data[0].lstrip(' ').split(' ')[4]
            self.stack.append(addr)
            data.pop(0)
        return self.stack

    def has_stack_trace(self):
        """Return true if stack trace data is in self.data"""
        return "#0" in self.data and "#1" in self.data

    def compare_stack(self, log):
        """Return true if stack trace (up to depth) is equal between self and log."""
        if len(self.stack) != len(log.stack):
            return False

        for x in range(0, len(self.stack)):
            DEBUG("Stack Trace(%d): %s %s" % (x, self.stack[x], log.stack[x]))
            if self.stack[x] != log.stack[x]:
                return False
        return True

    def serialize(self):
        """Return - (String) comma separated stack trace"""
        if not self.stack:
            return ""
        return ','.join(self.stack)

def main():
    usage  = "usage: %prog '/home/user/asan_logs/*.log'"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--depth', dest='depth', type='int', default=5, help='backtrace comparison depth')
    (opts, args) = parser.parse_args()
    if len(args) <= 1:
        parser.print_help()
        exit()

    files = args
    logs  = []
    for f in files:
        found_stack = False
        fd = open(f, 'r')
        new_log = AsanLog(fd.read(), fname=f, depth=opts.depth)
        fd.close()
        for log in logs:
            if log.compare_stack(new_log):
                log.dups.append(f)
                found_stack = True
                break
        if not found_stack:
            logs.append(new_log)

    for log in logs:
        print("[-] Unique stack (%s)" % (log.fname))
        print("\tDescription: %s" % log.desc)
        print("\tStack: \t%s" % '\n\t\t'.join(log.stack))
        print("\tDuplicates (%d)" % len(log.dups))
        for dup in log.dups:
            print("\t\t%s" % dup)

if __name__=='__main__':
    main()