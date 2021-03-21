import idaapi
import sark
#from reg_refs_forms import regRefPluginStarter, supported_procs
from oregami.oregami_gen import *
from oregami.regname import *


def AskStr(def_val, q_str):
    #without this line, waiting a few seconds for user input will cause the 'Please wait...' msgbox to jump and make the system freeze.
    orig_timeout = idaapi.set_script_timeout(0x7fffffff)
    ret = idc.AskStr(def_val, q_str)
    idaapi.set_script_timeout(orig_timeout)
    return ret
    
def get_regs(ea, all=True):
    reg = get_cursor_reg(ea)    

    if reg is None:
        return {}
        
    reg_set = set([reg])
    
    regs = proc_ops.get_basic_regs(ea, reg_set)
    
    
    if all:
        return regs
        
    if len(regs)<=1:
        return regs
        
    #need to pick only one reg
    reg = sorted(list(regs))[0] #first reg (alphabetically)
    reg = get_reg_user_name(ea, reg) #if renamed before, use it as default
    reg = AskStr(reg, 'Pick register')
    

    if reg is None: #exit
        return None
        
    #TODO: add check for user named reg
    if reg in regs:
        return [reg]
        
    for e_reg in regs:
        if reg==e_reg or reg==get_reg_user_name(ea, e_reg):
            return [e_reg]
    else:
        print 'No such reg in line'
        return []


def regnamePluginStarter(ea):
    #Get wanted reg
    regs = get_regs(ea, False)
    
    if regs is None:
        print 'Escaped'
        return
        
    regs = sorted(list(regs))
    
    assert len(regs)<=1
    if len(regs)==0:
        print 'No regs'
        return
    
    reg = regs[0]
    
    #Get new name    
    reg_new_name = AskStr(get_reg_user_name(ea, reg), 'New name for %s' % get_reg_full_name(ea, reg))
    
    if reg_new_name is None:
        return
        

    #Do renaming
    rename_reg(ea, reg, reg_new_name)
    
    
    
class RegnamePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "reGname"
    help = "Rename registers in their usage frame - only when used as a specific variable"
    wanted_name = "reGname"
    wanted_hotkey = "Shift+N"

    def init(self):
        self._prev_struct_name = ""
        
        proc_name = sark.idaapi.get_inf_structure().procName
        if proc_name not in supported_procs:
            print 'Regname plugin: No full support for this processor. Will do our best :)'
            #return idaapi.PLUGIN_SKIP

        return idaapi.PLUGIN_OK
        
    def term(self):
        pass

    def run(self, arg):
        start, _ = sark.get_selection()


        regnamePluginStarter(start)
        #regRefPluginStarter(start, tabMode=True, recursive_bool=False)
        

def PLUGIN_ENTRY():
    return RegnamePlugin()
