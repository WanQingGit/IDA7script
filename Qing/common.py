# coding=utf-8
"""
Created on 2019年10月17日

@author: WanQing
"""
import idc
import idautils
import struct
import re
from collections import defaultdict, OrderedDict

import idaapi
from idc import SegStart, FUNCATTR_START
from idc import SegEnd, DbgQword, ResumeProcess
from idc import refresh_debugger_memory, ResumeProcess
from idc import AnalyzeArea, GetEntryOrdinal
from idc import GetFunctionName, GetFunctionAttr, FUNCATTR_END
from idc import MakeComm, CheckBpt, SetColor, DbgDword
from idc import SegName, Name, AddBpt, CIC_FUNC, DelBpt
from idc import GetFirstModule, GetModuleName, GetNextModule
from idc import GetMnem, GetDisasm, GetMnem, GetRegValue
from idautils import Functions
from idaapi import run_requests, GraphViewer
from ida_dbg import request_step_into, request_continue_process
from idc import PrevHead, GetOpnd, isCode, GetFlags, MakeCode, GetManyBytes
from idc import StartDebugger, GetDebuggerEvent, LocByName
from idc import get_item_head

t2c = {"__int64": 'j', '__int16': 's', "__int32": 'i', "__int8": 'b',
       "int": "i", "short": 's', "char": 'c', "float": 'f', "void": 'p',
       "_DWORD": "i", "_QWORD": 'j', "_WORD": 's', "_BYTE": 'b',
       "unsigned __int64": 'j', "unsigned __int16": 's', "double": 'd', "long double": 'D'}
size2c = {1: 'b', 2: 's', 4: 'i', 8: 'j'}
basec = set(t2c.values())
idaapi.get_idati()
from Qing import config

try:
    if config.USE_DEBUG:
        from Qing.dbgutils import *

    else:
        raise Exception("default debugger")
except:
    DBG_INFO = 3
    DBG_WARN = 2
    DBG_ERR = 1


    class Debugger(object):

        def __init__(self, trace=True, level=DBG_INFO, suspend=True):
            self.trace = trace
            self.level = level
            self.suspend = suspend

        def __call__(self, *args, **kwargs):
            pass

        def debug(self):
            pass

        def info(self, *msg):
            if self.level >= DBG_INFO:
                print(msg)

        def warn(self, *msg):
            if self.level >= DBG_WARN:
                print(msg)

        def err(self, *msg):
            if self.level >= DBG_ERR:
                print(msg)

        def on(self):
            self.trace = True
            self.level = DBG_INFO

        def off(self):
            self.trace = False
            self.level = DBG_WARN

MAX_INT32 = (1 << 32) - 1
MAX_INT8 = (1 << 8) - 1
MAX_INT16 = (1 << 16) - 1

_common_dbg = Debugger()

_common_dbg.on()

Arch = None


def get_arch():
    global Arch
    """
    Get the target architecture.
    Supported archs: x86 32-bit, x86 64-bit, ARM 32-bit
    """
    arch = None
    bits = None
    _common_dbg()
    registers = idaapi.dbg_get_registers()
    if not registers:
        print('please select debugger first')
        return None
    for x in registers:
        name = x[0]
        if name == 'RAX':
            arch = 'amd64'
            bits = 64
            break
        elif name == 'EAX':
            arch = 'x86'
            bits = 32
            Arch = X86()
            break
        elif name == 'R0':
            arch = 'arm'
            bits = 32
            Arch = ARM32()
            break
        elif name == 'X0':
            arch = 'arm64'
            bits = 64
            Arch = ARM64()
            break

    return arch, bits


class ARCH(object):
    arch = None
    bits = 0

    def __init__(self):
        pass

    def ip(self):
        raise NotImplementedError

    def sp(self):
        raise NotImplementedError

    def ret(self):
        raise NotImplementedError

    def caller(self):
        raise NotImplementedError


class X86(ARCH):

    def __init__(self):
        super(X86, self).__init__()
        self.arch = 'x86'
        self.bits = 32

    def ip(self):
        return GetRegValue('EIP')

    def sp(self):
        return GetRegValue('ESP')

    def ret(self):
        """
        Get the return address stored on the stack or register
        """
        return DbgDword(GetRegValue('ESP'))

    def caller(self):
        return get_item_head(DbgDword(GetRegValue('ESP')) - 1)


class ARM64(ARCH):

    def __init__(self):
        super(ARM64, self).__init__()
        self.arch = 'arm64'
        self.bits = 64

    def ip(self):
        return GetRegValue('PC')

    def sp(self):
        return GetRegValue('SP')

    def ret(self):
        return GetRegValue('LR')  # X30

    def caller(self):
        return GetRegValue('LR') - 4


class ARM32(ARCH):

    def __init__(self):
        super(ARM32, self).__init__()
        self.arch = 'arm32'
        self.bits = 32

    def ip(self):
        return GetRegValue('PC')

    def sp(self):
        return GetRegValue('SP')

    def ret(self):
        return GetRegValue('LR')  # X30

    def caller(self):
        return GetRegValue('LR') - 4


get_arch()


class BaseObj(object):
    def __init__(self):
        self.usrdata = defaultdict(dict)

    def __getitem__(self, item):
        return self.usrdata[item]

    def __setitem__(self, key, value):
        self.usrdata[key] = value


class NumObj(object):

    def __init__(self, v):
        self.s = ""
        self.v = v

    def __repr__(self):
        return self.s

    def __hash__(self):
        return self.v.__hash__()

    def __eq__(self, other):
        if isinstance(other, NumObj):
            return self.v == other.v
        else:
            return self.v == other

    def __ne__(self, other):
        return not self.__eq__(other)


class Int64Obj(NumObj):

    def __init__(self, v):
        super(Int64Obj, self).__init__(v)
        ref = idc.DbgQword(v)
        if ref is not None:
            self.s = "0x%X" % v
        else:
            self.s = "0x%XL" % v
        self.ref = ref


class Int32Obj(NumObj):
    # _common_dbg()
    if Arch.bits == 64:
        def __init__(self, v):
            super(Int32Obj, self).__init__(v & MAX_INT32)
            self.s = "0x%x(%d)" % (v, self.v)
    else:
        def __init__(self, v):
            super(Int32Obj, self).__init__(v & MAX_INT32)
            ref = idc.read_dbg_dword(v)
            if ref is not None:
                self.s = "0x%X" % v
            else:
                self.s = "0x%XL" % v
            self.ref = ref


class FloatObj(NumObj):

    def __init__(self, v):
        _common_dbg()
        super(FloatObj, self).__init__(v)
        if not isinstance(v, float):
            try:
                byte_4 = struct.pack('I', v & MAX_INT32)
                float_num = struct.unpack('f', byte_4)
                v = float_num[0]
                self.s = "%.4f" % v
                self.v = v
            except:
                self.s = "not float"
        else:
            self.s = "%.4f" % v
        if v != v:  # nan
            self.v = None


class Int16Obj(NumObj):

    def __init__(self, v):
        super(Int16Obj, self).__init__(v & MAX_INT16)
        self.s = "0x%x(%d)" % (v, self.v)


class Int8Obj(NumObj):

    def __init__(self, v):
        super(Int8Obj, self).__init__(v & MAX_INT8)
        self.s = "0x%x(%d)" % (v, self.v)


t2o = {"j": Int64Obj, "i": Int32Obj, "f": FloatObj, 'b': Int8Obj, 's': Int16Obj, 'c': Int8Obj}
size2o = {1: Int8Obj, 2: Int16Obj, 4: Int32Obj, 8: Int64Obj}
WordObj = Int64Obj if Arch.bits == 64 else Int32Obj


def mod_base(module):
    module = "lib" + module + ".so"
    modules = idautils.Modules()
    if modules:
        for m in modules:
            if m.name.endswith(module):
                return m.base
    return idc.get_first_seg()


def common_cmt(ea, funclist, prefix=None, offset=0, override=False):
    if not funclist:
        return
    cmt = set()
    for func in funclist:
        name = idc.get_func_off_str(func + offset)
        cmt.add(name)
    try:
        scmt = ' '.join(cmt)
    except Exception as e:
        print(e)
        return

    if prefix:
        scmt = prefix + scmt
    if not override:
        socmt = idc.GetCommentEx(ea, 0)
        if socmt:
            ocmt = []
            if prefix and socmt.startswith(prefix):
                socmt = socmt[len(prefix):]
            oldcmt = socmt.strip().split("\n")
            for _cmt in oldcmt:
                ocmt.extend(_cmt.split(' '))
            ocmt = set(ocmt)
            ocmt -= cmt
        else:
            ocmt = None
        if ocmt:
            scmt += "\n" + ' '.join(ocmt)
    idc.MakeComm(ea, scmt)


def dbg_read_float(ea, size):
    bs = idc.read_dbg_memory(ea, size * 4)
    flts = struct.unpack(str(size) + "f", bs)
    try:
        s = ["%.3f" % f for f in flts]
        fltstr = " ".join(s)
        print(fltstr)
    except:
        pass
    return flts


def dbg_read_common(ea, n, size, t):
    bs = idc.read_dbg_memory(ea, size * n)
    data = struct.unpack(str(n) + t, bs)
    return data


def _read_result(data, n):
    # if n == 1:
    #     return data[0] #, str(data[0])
    # else:
    return data


# elif n <= 8:
#     return data, str(data)
# else:
#     return data, "\n" + str(data[:8]) + "..."


def read_int64(ea, n):
    val = dbg_read_common(ea, n, 8, "q")
    data = [Int64Obj(v) for v in val]
    # val=idc.read_dbg_qword(ea)
    # if n == 1:
    #     if idc.DbgQword(val[0]) is not None:
    #         return val[0], "0x%x" % val[0]
    #     else:
    #         return val[0], "0x%xL" % val[0]
    # else:
    return data


def read_int32(ea, n):
    val = dbg_read_common(ea, n, 4, "I")
    data = [Int32Obj(v) for v in val]
    return data


def read_int16(ea, n):
    val = dbg_read_common(ea, n, 2, "H")
    data = [Int16Obj(v) for v in val]
    return data


def read_int8(ea, n):
    val = dbg_read_common(ea, n, 1, "B")  # b or B
    data = [Int8Obj(v) for v in val]
    return data


def read_float(ea, n):
    val = dbg_read_common(ea, n, 4, "f")
    data = [FloatObj(v) for v in val]
    return data
    # if n == 1:
    #     return val[0], "%.4f" % val[0]
    # elif n <= 8:
    #     s = ["%.4f" % f for f in val]
    #     fltstr = " ".join(s)
    # else:
    #     s = ["\n"]
    #     for f in val[:8]:
    #         s.append("%.4f" % f)
    #     s.append("...")
    #     fltstr = " ".join(s)
    # return val, fltstr


# def type_is_array(tstr):
#     res = re.search("A(\d+)$", tstr)
#     if res:
#         return True,res.groups()[0]
#     else:
#         return False,1
#
# def type_is_ptr(tstr):
#     return  re.search("P+$", tstr)

def get_typestr(tif):
    word = Arch.bits >> 3;
    size = tif.get_size()
    typestr = tif.dstr().strip()
    typestr = re.sub("^(un)?signed\s+", "", typestr)
    if typestr in t2c:
        name = t2c[typestr]
    else:
        res = re.search("\[(\d+)\]", typestr)
        if res:
            rs = res.group()
            typestr = typestr.replace(rs, "")
            cout = int(res.groups(0)[0])
            unitsize = size / cout
            if typestr in t2c:
                name = t2c[typestr] + "A" + str(cout)
            elif unitsize in size2c:
                name = size2c[unitsize] + "A" + str(cout)
            else:
                name = typestr + "A" + str(cout)
        elif size == word:
            res = re.search("\s*\*+\s*$", typestr)
            if res:
                s, _ = res.span()
                np = len(res.group().strip())
                typestr = typestr[:s]
                if typestr in t2c:
                    name = t2c[typestr]
                else:
                    # np -= 1
                    name = typestr
                for _ in range(np):
                    name += "P"
            # elif typestr in t2c:
            #     name = t2c[typestr]
            # elif size in size2c:
            #     name = size2c[size]
            else:
                name = typestr
        elif size in size2c:
            name = size2c[size]
        else:
            name = typestr
    return name


def dict_compare(a, b, diff=None):
    if a == b:
        return True
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    res = True
    for k, va in a.iteritems():
        vb = b.get(k)
        if va != vb:
            if isinstance(va, dict) and isinstance(vb, dict):
                dif = {}
                isequal = dict_compare(va, vb, dif)
                if not isequal:
                    res = False
                    if diff:
                        diff[k] = (va, vb, dif)
            else:
                if diff:
                    diff[k] = (va, vb)
                res = False
    return res


def v2s(v):
    if isinstance(v, float):
        return "%.4f" % v
    elif isinstance(v, long):
        if v > 1024:
            return "0x%x" % v
        else:
            return "0x%x(%d)" % (v, v)
    elif isinstance(v, dict):
        strs = ["{"]
        count = 0
        for k, val in v.iteritems():
            strs.append(k)
            strs.append("=")
            strs.append(v2s(val))
            strs.append(";")
            if (count & 3) == 0:
                strs.append("\n")
            count += 1
        if strs[-1] == '\n':
            strs.pop()
        if strs[-1] == ';':
            strs.pop()
        strs.append("}")
        return "".join(strs)
    elif isinstance(v, list):
        if len(v) == 1:
            return v2s(v[0])
        else:
            strs = []
            if v[-1] == int:
                for i in v[:-2]:
                    strs.append(str(i))
                    strs.append("->")
                strs.append(v2s(v[-2]))
            else:
                for i in v[-8:]:
                    strs.append(v2s(i))
                    strs.append(",")
                if len(v) > 8:
                    strs[-1] = "..."
                else:
                    strs.pop()
            return "".join(strs)
    else:
        return str(v)


def dict_diff(a, b):
    if a == b:
        return None
    diff = {}
    if isinstance(a, list) and isinstance(b, list):
        la = len(a)
        lb = len(b)
        l = la if la <= lb else lb
        for i in range(l):
            if a[i] != b[i]:
                diff[i] = dict_diff(a[i], b[i])
    elif isinstance(a, dict) and isinstance(b, dict):
        keys = set()
        for k in a.iterkeys():
            keys.add(k)
        for k in b.iterkeys():
            keys.add(k)
        for k in keys:
            va = a.get(k)
            vb = b.get(k)
            if va != vb:
                diff[k] = dict_diff(va, vb)
    else:
        return a, b
    return diff


t2read = {"j": read_int64, "f": read_float, 'b': read_int8, 'c': read_int8, 's': read_int8, 'i': read_int32}
size2read = {1: read_int8, 2: read_int16, 4: read_int32, 8: read_int64}

# idc.set_func_cmt()
# idc.get_func_cmt()
# idc.FindFuncEnd()
# for head in idautils.Heads(547406432160, 547406433612L):
#     # if idc.isCode(idc.GetFlags(head)):
#         print(idc.GetDisasm(head))

# idc.GetMnem(547406432160)
# 'STP'
# idaapi.get_imagebase()
