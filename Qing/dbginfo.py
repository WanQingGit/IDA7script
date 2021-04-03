import idc
from Qing.func_utils import FuncArg, CallInfo, func_instr, FuncBps
import idaapi
from Qing.struct_utils import Structure, WatchVar, RegVar
from Qing.struct_utils import VAR_BASE, VAR_ARR
import collections
from Qing.common import Arch, WordObj
import traceback
import pickle
from Qing import config, common
from os.path import join


class DbgInfo(object):

    def __init__(self, dbginfo=None, module="Vuforia"):
        if dbginfo:
            self.funcarg = dbginfo.funcarg  # fea:arg
            self.watchvarlist = dbginfo.watchvarlist  # fea:varname
            self.regvarlist = dbginfo.regvarlist
            self.watchfunc = dbginfo.watchfunc
            self.tracebp = dbginfo.tracebp
            self.data_callinfo = dbginfo.data_callinfo
            self.userbp = dbginfo.userbp
            self.structure = dbginfo.structure
            self.instrtable = dbginfo.instrtable
            self.bplist = dbginfo.bplist
            self.bpregs = dbginfo.bpregs
            self.invalidbp = dbginfo.invalidbp

            self.module = dbginfo.module
            self.offset = dbginfo.offset
            self.enabletrace = dbginfo.enabletrace
        else:
            self.funcarg = {}  # fea:arg
            self.watchvarlist = {}  # fea:varname
            self.regvarlist = {}
            self.watchfunc = {}
            self.tracebp = set()
            self.data_callinfo = {}
            self.userbp = set()
            self.structure = {}
            self.instrtable = {}
            self.bplist = {}
            self.bpregs = {}
            self.invalidbp = None

            self.module = module
            self.offset = idaapi.get_imagebase()  # common.mod_base(module)
            self.enabletrace = False

    def load(self):
        self.funcarg = DbgInfo.config_load("funcarg", dict)
        self.watchvarlist = DbgInfo.config_load("watchvarlist", dict)
        self.watchfunc = DbgInfo.config_load("watchfunc", dict)
        self.tracebp = DbgInfo.config_load("tracebp", set)
        self.data_callinfo = DbgInfo.config_load("data_callinfo", dict)
        self.userbp = DbgInfo.config_load("userbp", set)
        self.structure = DbgInfo.config_load("structure", dict)
        self.instrtable = DbgInfo.config_load("instrtable", dict)
        self.bplist = DbgInfo.config_load("bplist", dict)
        self.bpregs = DbgInfo.config_load("bpregs", dict)

        data = DbgInfo.config_load("data", dict)
        if data:
            self.module = data["module"]
            self.offset = data["offset"]
            self.enabletrace = data['enabletrace']

    def save(self):
        DbgInfo.config_save(self.funcarg, "funcarg")
        DbgInfo.config_save(self.watchvarlist, "watchvarlist")
        DbgInfo.config_save(self.watchfunc, "watchfunc")
        DbgInfo.config_save(self.tracebp, "tracebp")
        DbgInfo.config_save(self.data_callinfo, "data_callinfo")
        DbgInfo.config_save(self.userbp, "userbp")
        DbgInfo.config_save(self.structure, "structure")
        DbgInfo.config_save(self.instrtable, "instrtable")
        DbgInfo.config_save(self.bplist, "bplist")
        DbgInfo.config_save(self.bpregs, "bpregs")
        data = {"module": self.module, "offset": self.offset, 'enabletrace': self.enabletrace}
        DbgInfo.config_save(data, "data")
        print("save dbginfo to " + config.DBGINFO_SAVE_PATH)

    @staticmethod
    def config_save(val, path):
        try:
            with open(join(config.DBGINFO_SAVE_PATH, path), "w") as fp:
                pickle.dump(val, fp)
            return True
        except Exception as e:
            print(e)
            return False

    @staticmethod
    def config_load(path, t):
        try:
            with open(join(config.DBGINFO_SAVE_PATH, path), "r") as fp:
                return pickle.load(fp)
        except Exception as e:
            print(e)
            if t is not None:
                return t()
            else:
                return None

    def bp_backup(self, suffix=""):
        nbp = idc.get_bpt_qty()
        bps = []
        for i in range(nbp):
            bp = idc.get_bpt_ea(i)
            bps.append((bp - self.offset, idc.check_bpt(bp)))
        return DbgInfo.config_save(bps, "breakpoints" + suffix)

    def bp_recover(self, remove=True, suffix=""):
        bplist = DbgInfo.config_load("breakpoints" + suffix, list)
        if not bplist:
            return False
        if remove:
            nbp = idc.get_bpt_qty()
            bps = []
            for i in range(nbp):
                bp = idc.get_bpt_ea(i)
                bps.append(bp)
            for bp in bps:
                idc.DelBpt(bp)
        for bp in bplist:
            ea = bp[0]
            addr = ea + self.offset
            idc.AddBpt(addr)
            idc.enable_bpt(addr, bp[1])
        return True

    def callinfo_backup(self, suffix=""):
        return DbgInfo.config_save(self.data_callinfo, "callinfo" + suffix)

    def callinfo_load(self, suffix="", assign=False):
        callinfo = DbgInfo.config_load("callinfo" + suffix, None)
        if assign and callinfo:
            self.data_callinfo = callinfo
        return callinfo

    def callinfo_clear(self):
        self.callinfo_backup("clearbak")
        self.data_callinfo.clear()

    def off_update(self):
        oldoffset = self.offset
        newoffset = idaapi.get_imagebase()  # common.mod_base(self.module)
        if oldoffset != newoffset:
            args = self.funcarg
            for _, funcarg in args.items():
                funcarg.addr = funcarg.ea + newoffset
            self.offset = newoffset
            for ea, funcbps in self.bplist:
                funcbps.addr = newoffset + funcbps.ea

    def bp_del(self, tracebp=True, clear=False):
        bplist = self.tracebp if tracebp else self.userbp
        for ea in bplist:
            try:
                idc.DelBpt(ea + self.offset)
            except Exception as e:
                print(e)
                self.tracebp.remove(ea)
        if clear:
            bplist.clear()

    def bp_load(self, userbp=True, tracebp=True):
        invalid = []
        if tracebp:
            for ea in self.tracebp:
                addr = ea + self.offset
                if idc.get_func_off_str(addr):
                    idc.AddBpt(addr)
                else:
                    invalid.append(addr)
        if userbp:
            for ea in self.userbp:
                addr = ea + self.offset
                if idc.get_func_off_str(addr):
                    idc.AddBpt(addr)
                else:
                    invalid.append(addr)
        if invalid:
            print("invalid ea:", str(invalid))
            self.invalidbp = invalid

    def bp_enable(self, enable, tracebp=True):
        bplist = self.tracebp if tracebp else self.userbp
        for ea in bplist:
            try:
                idc.enable_bpt(ea + self.offset, enable)
            except Exception as e:
                print(e)
                self.userbp.remove(ea)

    def bp_update(self):
        invalid = []
        for bp in range(idc.get_bpt_qty()):
            bpea = idc.get_bpt_ea(bp)
            offstr = idc.get_func_off_str(bpea)
            if not offstr:
                invalid.append(bpea)
                continue
            offstr = offstr.split("+")
            if len(offstr) == 1:
                self.userbp_add(bpea)
        if invalid:
            for bp in invalid:
                idc.del_bpt(bp)
            print ("invalid bp:", str(invalid))

    def addcallinfo(self, called, caller,tid=0):
        offcaller = idc.get_func_off_str(caller)
        ecalled = called - self.offset
        calledinfo = self.get_callinfo(ecalled,tid)
        if not offcaller:
            calledinfo.ncalled += 1
            return False
        ecaller = caller - self.offset
        l = offcaller.split("+")
        if len(l) > 1:
            eafn = ecaller - int(l[1], 16)
        else:
            eafn = ecaller
        callerinfo = self.get_callinfo(eafn,tid)
        callerinfo.addcall(ecalled, ecaller)
        if calledinfo.addcalled(ecaller):
            common.common_cmt(called, calledinfo.calledlist.keys(), "called by: ", self.offset, False)
        bpea = eafn + self.offset
        if self.enabletrace:
            if not idc.AddBpt(bpea):
                idc.enable_bpt(bpea, True)
        return True

    def userbp_add(self, ea):
        ea -= self.offset
        self.userbp.add(ea)
        if ea in self.tracebp:
            self.tracebp.remove(ea)

    def get_func_instr(self, addr):
        ea = addr - self.offset
        instr = self.instrtable.get(ea)
        if instr:
            return instr
        instr = func_instr(addr)
        self.instrtable[ea] = instr
        return instr

    def get_bp2(self, addr, notadd=False):
        ea = addr - self.offset
        bps = self.bplist.get(ea)
        if bps or notadd:
            return bps
        bps = FuncBps(ea, addr)
        bps.name = idc.get_func_off_str(addr)
        self.bplist[ea] = bps
        return bps

    def get_bp3(self, addr, notadd=False):
        ea = addr - self.offset
        bps = self.bpregs.get(ea)
        if bps or notadd:
            return bps
        bps = FuncBps(ea, addr)
        bps.name = idc.get_func_off_str(addr)
        self.bpregs[ea] = bps
        return bps

    def addbp(self, instr, ea=None):
        if ea is None:
            ea = idc.ScreenEA()
        func = idaapi.get_func(ea)
        startEA = func.startEA
        instrtable = self.get_func_instr(startEA)
        l = instrtable.get(instr)
        if l:
            for disa in l:
                pos = disa.offset + startEA
                if not idc.AddBpt(pos):
                    idc.EnableBpt(pos, True)

    def addbp2(self, ea=None):
        if ea is None:
            ea = idc.ScreenEA()
        func = idaapi.get_func(ea)
        startEA = func.startEA
        bps = self.get_bp2(startEA)
        if bps.add(ea):
            if not idc.AddBpt(ea):
                idc.EnableBpt(ea, True)
            return bps
        else:
            return False

    def delallbp2(self):
        self.bplist.clear()

    def addTracebp(self, ea=None):
        if ea is None:
            ea = idc.ScreenEA()
        rea = ea - self.offset
        self.tracebp.add(rea)
        if not idc.AddBpt(ea):
            idc.EnableBpt(ea, True)

    def delbp2(self, ea, offset, vea=None):
        funcbps = self.get_bp2(ea, True)
        if funcbps:
            varlist = funcbps.bps.get(offset)
            if varlist is None:
                return False
            if vea:
                if vea in varlist:
                    del varlist[vea]
                    if len(varlist) == 0:
                        idc.EnableBpt(ea + offset, False)
                    return True
            else:
                idc.enable_bpt(ea + offset, False)
                del funcbps.bps[offset]
                return True
        return False

    def delfuncbps(self, funcbps):
        ea = funcbps.ea
        bplist = self.bplist
        funcbps = bplist.get(ea)
        if funcbps:
            for offset, _ in funcbps.bps.items():
                idc.enable_bpt(offset + funcbps.addr, False)
            del bplist[ea]
            return True
        return False

    def isbp2(self, ea=None):
        try:
            if ea is None:
                ea = idc.ScreenEA()
            func = idaapi.get_func(ea)
            startEA = func.startEA
            bps = self.get_bp2(startEA, True)
            if bps:
                varlist = bps.isin(ea)
                return [varlist, bps]
            return False
        except Exception as e:
            # traceback.print_exc()
            return None

    def get_func_arg(self, afn):
        ea = afn - self.offset
        args = self.funcarg.get(ea)
        if not args:
            args = FuncArg(ea, afn)
            self.funcarg[ea] = args
        return args

    def is_func_watch(self, afn):
        ea = afn - self.offset
        return self.watchfunc.get(ea)

    def append_func_watch(self, afn):
        ea = afn - self.offset
        if ea in self.watchfunc:
            return None
        arg = self.get_func_arg(afn)
        self.watchfunc[ea] = arg
        return arg

    def del_func_watch(self, afn):
        ea = afn - self.offset
        watchfunc = self.watchfunc
        arg = watchfunc.get(ea)
        if arg:
            del self.funcarg[ea]
            del watchfunc[ea]
            return True
        else:
            return False

    def get_callinfo(self, ea, tid=0):
        data_callinfo=self.data_callinfo.get(tid)
        if data_callinfo is None:
            data_callinfo={}
            self.data_callinfo[tid]=data_callinfo
        if ea in data_callinfo:
            return data_callinfo[ea]
        else:
            callinfo = CallInfo(ea)
            data_callinfo[ea] = callinfo
            return callinfo

    def add_watch_var(self, ea, name, t, np):
        varlist = self.watchvarlist
        eav = ea.v
        var = varlist.get(eav)
        if var:
            return None
        var = WatchVar(name, t, ea, np)
        varlist[eav] = var
        return var

    def del_watch_var(self, key):
        varlist = self.watchvarlist
        var = varlist.get(key)
        if var:
            del varlist[key]
            return var
        return None

    def add_reg_var(self, ea, name, t, np):
        varlist = self.regvarlist
        var = varlist.get(name)
        if var:
            return None
        var = RegVar(name, t, ea, np)
        varlist[name] = var
        return var

    def del_reg_var(self, name):
        varlist = self.regvarlist
        var = varlist.get(name)
        if var:
            del varlist[name]
            return var
        return None

    def watch_func_arg(self, afn):
        try:
            ea = afn - self.offset
            args = self.funcarg.get(ea)
            arginfos = args.arginfos
            varnames = args.watchvar
            n = args.narg - 1
            arguments = args.arguments
            for name in varnames:
                info = arginfos[name]
                ea = arguments[name][n]
                if ea.ref is not None:
                    v = self.read_value(info.type, ea, info.np)
                    args.append_watchvar(name, v, n)
            args.nwatch += 1
        except Exception as e:
            print("watch function {} argument err occur {}".format(ea, str(e)))
            traceback.print_exc()

    def read_var(self, var):
        try:
            if isinstance(var, WatchVar):
                v = self.read_value(var.t, var.ea, var.np)
            else:
                ea = var.ea
                if isinstance(ea, str):
                    ea = WordObj(idc.get_reg_value(var.ea))
                else:
                    sp = Arch.sp()
                    ea = WordObj(sp + ea)
                v = self.read_value(var.t, ea, var.np)
            var.push_value(v)
            return v
        except Exception as e:
            return None

    def read_value(self, t, ea, np):
        fn = common.t2o.get(t)
        if np == 0:
            return [fn(ea.v)]
        v = [ea]
        n = np - 1
        for _ in range(n):
            ea = WordObj(ea.ref)
            if ea.ref is not None:
                v.append(ea)
            else:
                break
        if len(v) == np:
            if fn:
                val = fn(ea.ref)
            else:
                val = self.read_struct(t, ea, 1)  # (t, ea.v, 1)
                val = val[0]
            v.append(val)
        v.append(int)
        return v

    def read_struct(self, stname, ea, num=1):
        if not ea or ea.ref is None:
            return None
        st = self.structure.get(stname)
        if not st:
            st = Structure(stname)
            self.structure[stname] = st
        st_member = st.member
        st_size = st.size
        res = []
        ea = ea.v
        for i in range(num):
            v = collections.OrderedDict()
            for offset, m in st_member.items():
                if m.flag & VAR_ARR:
                    count = m.num
                else:
                    count = 1
                if m.flag & VAR_BASE:
                    try:
                        fn = common.t2read.get(m.tstr)
                        val = fn(ea + offset, count)
                        if count == 1:
                            val = val[0]
                    except Exception as e:
                        print("{} parser err: {}".format(m.tstr, e))
                else:
                    # if m.flag&VAR_PTR:
                    addr = WordObj(ea + offset)
                    val = []
                    for _ in range(m.np):
                        addr = addr.ref
                        if addr is not None:
                            addr = WordObj(addr)
                            val.append(addr)
                        else:
                            break
                    if len(val) == m.np:
                        sval = self.read_struct(m.tstr, addr, count)
                        if count == 1 and sval:
                            sval = sval[0]
                        val.append(sval)
                    if len(val) == 1:
                        val = val[0]
                    else:
                        val.append(int)
                v[m.name] = val
            res.append(v)
            ea += st_size
        return res
