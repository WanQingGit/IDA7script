import ida_nalt
import ida_kernwin
import sark
import re
import idc
import oregami.oregami_gen as oregami_gen
import ida_frame
import ida_funcs
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
import _ida_kernwin
import idaapi
from oregami.oregami_gen import *
from oregami.regname import *
import ida_struct

#TODO: if rw, dont change type
  
class TyperegterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "TypeREGter"
    help = "Set type for regs in their usage frame - only when used as a specific variable"
    wanted_name = "TypeREGter"
    wanted_hotkey = "Shift+T"

    def init(self):
        self._prev_struct_name = ""
        
        proc_name = sark.idaapi.get_inf_structure().procName
        if proc_name not in supported_procs:
            print 'Typeregter plugin: No full support for this processor. Will do our best :)'
            #return idaapi.PLUGIN_SKIP

        return idaapi.PLUGIN_OK
        
    def term(self):
        pass

    def run(self, arg):
        start, _ = sark.get_selection()


        typeregterPluginStarter(start)
        #regRefPluginStarter(start, tabMode=True, recursive_bool=False)
        

def PLUGIN_ENTRY():
    return TyperegterPlugin()
    
    
    
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

def get_type():
    #without this line, waiting a few seconds for user input will cause the 'Please wait...' msgbox to jump and make the system freeze.
    orig_timeout = idaapi.set_script_timeout(0x7fffffff)
    
    struc_type = ida_kernwin.choose_struc('Choose type')
    idaapi.set_script_timeout(orig_timeout)
    
    if struc_type is None:
        return None
        
    #print struc_type
    type_name = ida_struct.get_struc_name(struc_type.id)
    return type_name
    
    print type(a)
    type_name = AskStr('', 'Type for %s' % get_reg_full_name(ea, reg))
    if type_name is None:
        print 'Escaped'
        return None
        
    if ida_struct.get_struc_id(type_name)==0xffffffff:
        print 'Not a type'
        return None
        
    return type_name

def typeregterPluginStarter(ea):
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
    
    #Get type name    
    type_name = get_type()
    
    if type_name is None:
        return
        

    #Do renaming
    typeset_reg(ea, reg, type_name)
    

    
########################             
#### Type set logic ####
########################
        
def get_cur_type(ea, reg):
    opnds = sark.Line(ea).insn.operands
    for i in range(len(opnds)):
        if '[%s]' % get_reg_user_name(ea, reg) in opnds[i].text:
            str_id = ida_struct.get_struc_id(type_name)
            idc.op_stroff(ea, i, str_id, 0)
        
def typeset_reg_for_address(ea, reg, type_name):
    opnds = sark.Line(ea).insn.operands
    for i in range(len(opnds)):
        if ('[%s]' % get_reg_user_name(ea, reg) in opnds[i].text) or ('[%s,' % get_reg_user_name(ea, reg) in opnds[i].text):
            str_id = ida_struct.get_struc_id(type_name)
            idc.op_stroff(ea, i, str_id, 0)
            ida_nalt.set_aflags(ea, ida_nalt.get_aflags(ea) | ida_nalt.AFL_ZSTROFF)
    
def typeset_reg(ea, reg, type_name):
    found_lines, found_breaks, found_outbreaks = oregami_gen.get_refs(ea, reg)
    #eas = list(set(found_lines.keys()) - set(found_breaks.keys()))
    eas = found_lines.keys()
    
    t_eas = []
    for ea in found_lines.keys():
        if found_lines[ea]=='r':
            t_eas += [ea]
            
    
    for ea in t_eas:
        typeset_reg_for_address(ea, reg, type_name)
    
    
###########
## debug ##
###########

def debug(s):
    #return
    print s
    

#if reg was renamed - get full name    
def get_reg_full_name(ea, reg):
    if reg not in get_reg_names(ea):
        return reg
        
    return '%s {%s}' % (get_reg_names(ea)[reg], reg)
    
    
def get_reg_names(ea):
    from idautils import GetRegisterList
    from ida_frame import find_regvar
    from ida_funcs import get_func
    
    d = {}

    for canon in GetRegisterList():
        regvar = find_regvar(get_func(ea), ea, canon)
        if regvar:
            d[canon] = regvar.user
            
    return d  
    
    
