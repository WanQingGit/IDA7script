# -*- coding:utf-8 -*-

# ======= import =======
from Qing import common
from Qing.common import *
import idautils

regs = idaapi.dbg_get_registers()


def addBpFuncHead():
    for ea in idautils.Functions():
        cfunc = idaapi.get_func(ea)
        if cfunc.end_ea - cfunc.start_ea > 20:
            if not idc.add_bpt(ea):
                idc.EnableBpt(ea, True)


def delBpFuncHead():
    for ea in idautils.Functions():
        idc.del_bpt(ea)


def func_rename(prefix="sub_", npref="fn_", func_list=None, offset=0):
    # common.Debugger().debug()
    if not func_list:
        func_list = idautils.Functions()  # 获取所有函数列表
    for func in func_list:
        func += offset
        name = idc.GetFunctionName(func)  # 获取函数名称
        # #             idc.del_func(func)
        if name.startswith(prefix):
            #     if( "XXXXXXXXX" in name) :
            #             address = idc.LocByName(name)
            new_name = name.replace(prefix, npref, 1);
            idc.MakeName(func, new_name)  # 重命名函数名


_func_dbg = Debugger()

_func_dbg.off()


class CallInfo(object):

    def __init__(self, afn):
        self.afn = afn
        # self.name = name
        self.calllist = {}
        self.calledlist = {}
        self.ncalled = 0

    def addcall(self, ea, off):
        if ea in self.calllist:
            callset = self.calllist[ea]
        else:
            callset = set()
            self.calllist[ea] = callset
        callset.add(off)

    def addcalled(self, ea):
        calledlist = self.calledlist
        self.ncalled += 1
        if ea in calledlist:
            calledlist[ea] += 1
            return False
        else:
            calledlist[ea] = 1
            return True


class ArgInfo(object):

    def __init__(self):
        self.size = 0
        self.isreg = None
        self.name = None
        self.position = None
        self.type = None
        self.np = 0
        self.fn = None


class FuncBps(BaseObj):

    def __init__(self, ea, addr):
        super(FuncBps, self).__init__()
        self.ea = ea
        self.addr = addr
        self.name = None
        self.bps = {}  # off:{"var":var,"indexs":[]}
        # or off:{"var":reg,"indexs":[]}

    def __repr__(self):
        return self.name

    def add(self, ea):
        offset = ea - self.addr
        if offset in self.bps:
            return False
        self.bps[offset] = {}
        return True

    def isin(self, ea):
        offset = ea - self.addr
        return self.bps.get(offset)

    def addvar(self, var, offset=None):
        if offset is not None:
            varlist = self.bps[offset]
            ea = var.ea
            if ea in varlist:
                return False
            varlist[ea] = {"var": var, "indexs": []}
            return True
        for offset, varlist in self.bps.iteritems():
            res = False
            if self.addvar(var, offset):
                res = True
        return res

    def remove(self, ea):
        offset = ea - self.addr
        bps = self.bps
        if offset in bps:
            del bps[offset]
            return True
        return False


class FuncArg(BaseObj):
    MAX_SAVE = 2000
    OVER_SAVE = 200

    def __init__(self, ea, addr):
        super(FuncArg, self).__init__()
        self.ea = ea
        self.addr = addr
        self.arginfos = OrderedDict()
        self.arguments = OrderedDict()
        self.pointer = {}
        self.watchvar = set()
        self.watchptr = False
        self.cache_args = "empyt"
        self.cache_extra = ""
        self.refresh = True
        self.refresh_extra = True
        self.nwatch = 0
        self.narg = 0
        self.cfunc = idaapi.decompile(addr)
        self.parse_argument()
        # self.watch={}

    @staticmethod
    def append(k, v, table):
        args = table.get(k)
        if args:
            if len(args) > FuncArg.MAX_SAVE:
                args = args[-FuncArg.OVER_SAVE:]
                table[k] = args
            args.append(v)
        else:
            args = [v]
            table[k] = args

    def add_var_watch(self, name):
        self.watchvar.add(name)

    def append_arg(self, name, v):
        FuncArg.append(name, v, self.arguments)
        self.refresh = False

    def append_watchvar(self, name, v, n):
        table = self.pointer.get(name)
        if not table:
            table = OrderedDict()
            self.pointer[name] = table
        table[n] = v
        self.refresh_extra = False

    def argument_str(self):
        if self.refresh:
            return self.cache_args
        strs = []
        for k, v in self.arguments.iteritems():
            strs.append(k)
            strs.append(":")
            if len(set(v)) == 1:
                strs.append(str(v[0]))
                strs.append("\n")
            else:
                for i in v[-5:]:
                    strs.append(str(i))
                    strs.append(', ')
                strs[len(strs) - 1] = '\n'
        self.cache_args = "".join(strs)
        self.refresh = True
        return self.cache_args

    def compare_extra(self, a=-2, b=-1):
        for k, v in self.pointer.iteritems():
            dta = v[a]
            dtb = v[b]
            alen = len(dta)
            blen = len(dtb)
            if alen != blen:
                minlen = alen if alen <= blen else blen
                print(self.sValByName([a, b], k, 0, minlen))
            for i in range(1, alen):
                itema = dta[i]
                if not itema == dtb[i]:
                    if isinstance(itema, dict):
                        diff = {}
                        isequal = dict_compare(itema, dtb[i], diff)
                        if not isequal:
                            print v2s(isequal)
                    else:
                        print(self.sValByName([-2, -1], k, 0, i + 1))

    def extra_str(self, n=-1):
        if self.refresh_extra:
            return self.cache_extra
        strs = []
        if n < 0:
            n = self.narg + n
        for k, v in self.pointer.iteritems():
            dt = v.get(n)
            if not dt:
                continue
            strs.append(k)
            strs.append(':')
            strs.append(v2s(dt))
            # count = 0
            # length = len(dt)-1
            # for i in dt:
            #     count += 1
            #     if count < length:
            #         strs.append(str(i))
            #         strs.append("->")
            #     else:
            #         strs.append(v2s(i))
            #         break
            strs.append('\n')
        self.cache_extra = "".join(strs)
        self.refresh_extra = True
        return self.cache_extra

    # n[-1,-2]
    def sValByName(self, n, k, s, end):
        strs = ["---------", k, "---------\n"]
        v = self.pointer.get(k)
        if not v:
            return
        for i in n:
            data = v[i]
            strs.append(str(i))
            strs.append(':')
            # length = len(data)-1
            for index in range(s, end):
                strs.append(v2s(data[index]))
                strs.append("->")
            strs[-1] = "\n"
        return "".join(strs)

    def parse_argument(self):
        cfunc = self.cfunc
        arginfos = self.arginfos
        args = cfunc.arguments
        stack_off = 1
        isArm = isinstance(Arch, ARM64)
        word = Arch.bits >> 3
        for i, var in enumerate(args):
            info = ArgInfo()
            name = var.name
            info.name = name
            size = var.width
            info.size = size
            position = var.location
            if position.is_reg():
                if not isArm:
                    stack_off -= 1
                    continue
                info.isreg = True
                info.position = regs[i][0]
                # reg = (position.get_reginfo() >> 3) - 1
            else:
                if Arch.bits == 64:
                    off = (i - 8) << 3
                    info.position = off
                else:
                    info.position = (i + stack_off) << 2
            t = common.get_typestr(var.tif)
            info.type = t
            fn = t2o.get(t)
            if fn:
                info.fn = fn
            else:
                fn = size2o.get(size)
                if fn:
                    info.fn = fn
                else:
                    print("unsupport size {} of filed {} {}".format(size, t, name))
                if size == word:
                    res = re.search("P+$", t)
                    if res:
                        r = res.span()
                        head = r[0]
                        np = r[1] - head
                        t = t[:head]
                        info.type = t
                        info.np = np
            arginfos[name] = info

    def analyze(self):
        _func_dbg()
        read_reg = idc.read_dbg_qword if Arch.bits == 64 else idc.read_dbg_dword
        try:
            sp = Arch.sp()
        except:
            return
        for name, varinfo in self.arginfos.iteritems():
            if varinfo.isreg:
                # reg = (position.get_reginfo() >> 3) - 1
                val = idc.GetRegValue(varinfo.position)
            else:
                val = read_reg(varinfo.position + sp)
            v = varinfo.fn(val)
            self.append_arg(name, v)
        self.narg += 1
        if self.narg > FuncArg.MAX_SAVE:
            self.narg = FuncArg.OVER_SAVE


from Qing.DisasmParser import DisasmInfo


def func_instr(ea=None):
    if ea is None:
        ea = idc.ScreenEA()
    instrtable = {}
    func = idaapi.get_func(ea)
    startEA = func.startEA
    endEA = func.endEA
    for head in idautils.Heads(startEA, endEA):
        disa = idc.GetDisasm(head)
        disares = DisasmInfo(disa, head - startEA)
        insrt = disares.inst
        t = instrtable.get(insrt)
        if not t:
            t = []
            instrtable[insrt] = t
        t.append(disares)
    return instrtable


def func_save(path="data.bin"):
    _func_dbg()
    offset = idaapi.get_imagebase()
    funclist = []
    for ea in idautils.Functions():
        funcname = idc.get_func_off_str(ea)
        if funcname[:3].upper() == "FN_":
            funclist.append(ea - offset)
    with open(path, "wb") as fp:
        length = len(funclist)
        bs = struct.pack("I", length)
        fp.write(bs)
        for ea in funclist:
            bs = struct.pack("Q", ea)
            fp.write(bs)


def func_load(path="data.bin", offset=None):
    _func_dbg()
    if not offset:
        offset = idaapi.get_imagebase()
    with open(path, "rb") as fp:
        bs = fp.read(4)
        length = struct.unpack("I", bs)[0]
        content = fp.read()
        if len(content) == length << 3:
            funclist = struct.unpack(str(length) + "Q", content)
            return [ea + offset for ea in funclist]
        else:
            return None
