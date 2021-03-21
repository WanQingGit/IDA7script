# coding=utf-8
"""
Created on 2019.10.11

@author: WanQing
"""


import re

class DisasmInfo(object):

    def __init__(self, disasm=None, offset=None):
        self.offset = offset
        self.inst = ""
        self.cmt = ""
        self.vars = None
        if disasm:
            self.parse(disasm)

    def __str__(self):
        return " %s %s %s" % (self.inst, " ".join(self.vars), self.cmt)

    def __repr__(self):
        return " %s %s %s" % (self.inst, " ".join(self.vars), self.cmt)

    def parse(self, disasm):
        res=re.search("^[a-zA-Z.]+", disasm)
        i = res.group()
        self.inst=i
        disasm=disasm[len(i):]
        try:
            i = disasm.index(';')
            self.cmt = disasm[i + 1:]
            disasm = disasm[:i]
        except:
            self.cmt = ''
        disasm = disasm.strip()
        self.vars = disasm.split(',')
