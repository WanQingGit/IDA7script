# coding=utf-8
import time
from Qing.common import *
from Qing.dbginfo import DbgInfo
from Qing.DisasmParser import DisasmInfo
import pickle
import os
from Qing import config, callviewer
from Qing.config import DebugMode
from collections import defaultdict
from Qing.QtArgAnalyzer import VarAnalyzer
from Qing.QtVarWatcher import VarWatcher
from Qing.QtTracer import FuncTracer
from idc import DbgDword, GetRegValue

_vars = dir()
if "CMT_OVERRIDE" not in _vars:  # override
    CMT_OVERRIDE = False
else:
    print("use defined var")


def pathsuffix():
    return time.strftime('%m.%d-%H.%M', time.localtime(time.time()))


def blr_info_add(ea, dbghk, blrinfo):
    disasm = dbghk.disasm
    r = disasm.vars[0]
    addr = idc.GetRegValue(r)
    if ea in blrinfo:
        d = blrinfo[ea]
        d.add(addr)
    else:
        d = set()
        d.add(addr)
        blrinfo[ea] = d
    common_cmt(ea, blrinfo[ea], CMT_OVERRIDE)


def ret_callback(ea, hook, _):
    func = idaapi.get_func(ea)
    startEA = func.startEA
    arginfo = hook.dbginfo.get_func_arg(startEA)
    # arginfo.get_watch_value()
    # arginfo.compare_extra()


try:
    if not dbg:
        raise Exception("Init...!")
except:
    dbg = Debugger(trace=True, suspend=True)
    print("init debug var...")
    libDict = {}

dbg()


class MyDbgHook(idaapi.DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def __init__(self, dbginfo=None, load=False,
                 path=None):
        idaapi.DBG_Hooks.__init__(self)
        self.disasm = DisasmInfo()
        self.go = False
        if path:
            self.path = path
        else:
            self.path = os.getcwd() + "/dbginfo"
        self.go_err = False
        self.needinit = True
        self.thredshold = 256
        self.step = 0
        self.inscallback = defaultdict(list)
        self.initfn()
        if dbginfo:
            self.dbginfo = DbgInfo(dbginfo)
            self.dbginfo.off_update()
            self.bp_load()
        else:
            if load and os.path.isfile(self.path):
                with open(path, "r") as fp:
                    self.dbginfo = pickle.load(fp)
                self.dbginfo.off_update()
                self.bp_load()
            else:
                dbginfo = DbgInfo()
                self.dbginfo = dbginfo
                self.ubp_update(False)
                # self.bp_load()
        varAnalyzer = VarAnalyzer(self.dbginfo)
        self.varAnalyzer = varAnalyzer
        varAnalyzer.Show()
        varAnalyzer.load_data()
        varWatcher = VarWatcher(self.dbginfo)
        self.varWathcer = varWatcher
        varWatcher.Show()
        varWatcher.load_data()
        funcTracer = FuncTracer(self.dbginfo)
        self.funcTracer = funcTracer
        funcTracer.Show()

    def initfn(self):
        pass
        # self.registerfn("BLR", blr_info_add, {})
        # self.registerfn("RET", ret_callback, None)

    def save(self, path=None):
        if not path:
            path = self.path
            self.dbginfo.off_update()
        try:
            with open(path, "w") as fp:
                pickle.dump(self.dbginfo, fp)
        except:
            try:
                self.dbginfo.save()
            except Exception as err:
                print(err)

    def registerfn(self, instruction, callback, data=None):
        self.inscallback[instruction].append((callback, data))

    def dbgclear(self):
        self.dbginfo = DbgInfo()
        self.dbginfo.bp_update()

    def ubp_update(self, clear=True):
        dbginfo = self.dbginfo
        if clear:
            dbginfo.userbp.clear()
        dbginfo.bp_update()

    def bp_load(self):
        self.dbginfo.bp_load()

    def ubp_enable(self, enable=True):
        self.dbginfo.bp_enable(enable, False)

    def bp_del(self):
        self.dbginfo.bp_del(True, False)

    def clear_fninfo(self):
        self.dbginfo.data_callinfo.clear()

    def load(self, path=None):
        try:
            with open(path if path else self.path, "r") as fp:
                self.dbginfo = pickle.load(fp)
        except:
            self.dbginfo = DbgInfo()
            self.dbginfo.load()
        self.dbginfo.off_update()
        self.bp_load()

    def __handle(self, ea, tid=0):
        self.step += 1
        mode = config.DEBUG_MODE
        dbginfo = self.dbginfo
        if mode == DebugMode.NORMAL:
            self.go = False
            if self.step > self.thredshold:
                self.save()
                self.thredshold = int(self.step << 1) + 5
        elif mode & DebugMode.VIOLENCE:
            go = True
            watcher = self.varWathcer
            varlist = dbginfo.watchvarlist
            for _, var in varlist.iteritems():
                if dbginfo.read_var(var):
                    values = var.values
                    lenv = len(values)
                    if lenv > 1:
                        if values[-1] != values[-2]:
                            go = False
                            watcher.watchnode_update(var)
                        elif lenv > 2 and values[0] == values[-1]:
                            idc.DelBpt(ea)
            self.go = go
            return
        elif mode & DebugMode.DISBP:
            idc.enable_bpt(ea, False)
            self.go = True
            return
        else:
            self.go = True
        varinfo = dbginfo.isbp2(ea)
        if varinfo and varinfo[0]:
            bps = varinfo[1]
            varlist = varinfo[0]
            watcher = self.varWathcer
            for _ea, varinfo in varlist.iteritems():
                var = varinfo['var']
                values = var.values
                index = len(values)
                issuccess = dbginfo.read_var(var)
                # if isinstance(var,WatchVar):
                if issuccess:
                    varinfo['indexs'].append(index)
                if mode != DebugMode.MONITOR:
                    watcher.watchnode_update(var)
                else:
                    if len(values) > 1 and values[-1] != values[-2]:
                        self.go = False
            if not self.go:
                watcher.bpnode_update(bps)
            else:
                return
        elif varinfo is None:
            return
            # if self.go:
        #     return
        disasmRes = self.disasm
        funcOffset = idc.GetFuncOffset(ea)  # fn_9FF5C8+C
        if not funcOffset:
            print("function 0x%X is not a useful address" % ea)
            return
        funcInfo = funcOffset.split("+")
        disasm = idc.GetDisasm(ea)
        disasmRes.parse(disasm)
        if len(funcInfo) == 1:
            caller = Arch.caller()
            dbginfo.addcallinfo(ea, caller, tid)
            argument = dbginfo.is_func_watch(ea)
            if argument:
                joinstr = "\nparameter analysis results\n"
                argument.analyze()
                arg_cmt = argument.argument_str()
                print(arg_cmt)
                self.varAnalyzer.argnode_update(argument)
                if argument.watchptr:
                    dbginfo.watch_func_arg(ea)
                    extra_cmt = argument.extra_str()
                    print(extra_cmt)
                    self.varAnalyzer.watchnode_update(argument)
                    arg_cmt = "\n".join([arg_cmt, extra_cmt])
                old = idc.get_func_cmt(ea, True)
                try:
                    ncmt = joinstr.join([old.split(joinstr)[0], str(arg_cmt)])
                    idc.set_func_cmt(ea, ncmt, True)
                except Exception as err:
                    print(err)
        if disasmRes.inst in self.inscallback:
            for fn, data in self.inscallback[disasmRes.inst]:
                fn(ea, self, data)

    def addretbp(self, ea=None):
        dbg.debug()
        self.dbginfo.addbp("RET", ea)

    def unhook(self, *args):
        # dbginfo = self.dbginfo
        idaapi.DBG_Hooks.unhook(self, *args)
        # self.dbginfo.bp_enable(False)
        #     idc.DelBpt(ea)
        # dbginfo.tracebp.clear()

    def __del__(self):
        try:
            self.save(self.path + pathsuffix())
        except:
            pass

    # def show(self):
    #     self.dbginfo.off_update()
    #     graph = callviewer.CallGraph("call viewer", self.dbginfo.data_callinfo, self.dbginfo.offset)
    #     graph.Show()

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("MyDbgHook : Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        print("MyDbgHook : Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_library_unload(self, pid, tid, ea, info):
        print("MyDbgHook : Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        return 0

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        libDict[name] = (base, size, pid, tid,)
        print("MyDbgHook : Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (
            pid, tid, ea, name, base, size))
        # self.dbginfo.off_update()

    def dbg_process_detach(self, pid, tid, ea):
        print("MyDbgHook : Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        libDict[name] = (base, size, pid, tid,)
        print("MyDbgHook : Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))

    def dbg_bpt(self, tid, ea):
        print("MyDbgHook : Break point at %s[0x%x] pid=%d" % (idc.get_func_off_str(ea), ea, tid))
        if self.needinit:
            dbg.debug()
            self.dbginfo.off_update()
            self.needinit = False
        self.__handle(ea, tid)
        if self.go:
            idaapi.continue_process()
        return 0

    def dbg_suspend_process(self):
        print("MyDbgHook : Process suspended")

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        print("MyDbgHook : Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        return 0

    def dbg_trace(self, tid, ea):
        print("MyDbgHook : Trace tid=%d ea=0x%x" % (tid, ea))
        return 0

    def dbg_step_into(self):
        eip = Arch.ip()  # EIP
        print("MyDbgHook : Step into  0x%x %s" % (eip, idc.GetDisasm(eip)))
        self.__handle(eip)

    def dbg_run_to(self, pid, tid=0, ea=0):
        print("MyDbgHook : Runto: tid=%d" % tid)
        idaapi.continue_process()

    def dbg_step_over(self):
        eip = Arch.ip()  # EIP
        print("MyDbgHook : dbg_step_over  0x%x %s" % (eip, idc.GetDisasm(eip)))
        self.__handle(eip)


try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
        debughook.varAnalyzer.Close(0)
        debughook.varWathcer.Close(0)
        debughook.funcTracer.Close(0)
        dbg.debug()
        debughook = MyDbgHook(debughook.dbginfo)
    else:
        debughook = MyDbgHook(load=True)
except Exception as _e:
    debughook = MyDbgHook()

debughook.hook()
idc.a = debughook

# count = 0
# class DumpHook(DBG_Hooks):
#     def dbg_bpt (self,tid,ea):
#         global count
#         count += 1;
#         print "[*] Hit: 0x%08x the %d time\n" % (ea, count)
#         data = "\xBE\x91\x0A\xF3\x9A\x26\xA4\xA9\x92\xC6\xFD\x01\xA1\x43\xED\x19"
#         idaapi.dbg_write_memory(idc.GetRegValue("r7"), data)
#         return 1
#
# idc.SetBptAttr(0x8050a42e, idc.BPTATTR_FLAGS, idaapi.BPT_ENABLED|idaapi.BPT_TRACE)
# idc.DelBpt(idc.GetBptEA(bp))
# import idaapi
# start_address = 0x47e060
# data_length = 90000
# data = idaapi.dbg_read_memory(start_address , data_length)
# fp = open('d:\\dump1', 'wb')
# fp.write(data)
# fp.close()
