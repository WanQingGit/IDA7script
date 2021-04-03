from collections import deque
from idc import *
import sark
import sys 
import oregami_gen


############################
###### Internal funcs ######
############################    

def _get_call_ea(ea):
    func_eas = []
    for xref in sark.Line(ea).xrefs_from:
        #if it is not a code xref, skip
        if xref.iscode==False:
            continue
        #if we reference somewhere outside the func - it is a call
        if sark.Function(xref.to).start_ea != sark.Function(ea).start_ea:
            func_eas += [xref.to]
      
    num_refs = len(func_eas)
    if num_refs==0:
        return None
    elif num_refs==1:
        return func_eas[0]
    else:
        # weird - expected only one xref outside the func.
        print "Err: < %x > Found more than one reference outside the func. Isn't supposed to happen." % ea
        return None
        
def _is_call(ea):
    if _get_call_ea(ea) is None:
        return False
    else:
        return True
        
def _call_op(ea, reg):
    mnem = sark.Line(ea).insn.mnem
    
    if (mnem in _calls_with_regs.keys()):
        if (reg in _calls_with_regs[mnem]):
            #if the reg is restored - it is no operation
            return ''
        else:
            #if the reg is not restored - assume it was changed
            #may technically be rw (even registers used as input are included here), but this is the safest bet
            return 'w'
    elif (mnem in _calls_with_funcs.keys()):
        return _calls_with_funcs[mnem](ea, reg)
    
    else:
        print "ERR: < %x > function call of type %s was not yet defined. Ignoring (assuming didn't change reg)" % (ea, mnem)
        return ''
        
def _op_details(mnem, operand_num, ea):
    if (mnem,operand_num) not in _op_details_l:
        return None
    if isinstance(_op_details_l[(mnem,operand_num)], types.FunctionType):
        return _op_details_l[(mnem,operand_num)](ea)
    elif isinstance(_op_details_l[(mnem,operand_num)], types.TupleType):
        return _op_details_l[(mnem,operand_num)]
    else:
        return None
        
def _get_regs_in_operand(ea, operand_idx):
    opnd = sark.Line(ea).insn.operands[operand_idx]
    reg_set = opnd.regs
        
    #can't be sure that sark got all regs - for example, 'ld16.bu d0, [a12]' doens't recognise a12
    from idautils import GetRegisterList
    all_regs = GetRegisterList()

    for e_reg in all_regs:            
        if '[%s]'%e_reg in opnd.text:
            reg_set |= set([e_reg])
            
    #check also for special user names
    reg_names_dict = oregami_gen.get_reg_user_to_canon(ea)
    all_user_regs = reg_names_dict.keys()
    for e_reg in all_user_regs:            
        if '[%s]'%e_reg in opnd.text:
            reg_set |= set([reg_names_dict[e_reg]])        

            
    #ARM - add recognition of operands of the shape 'R3,LSL#1'
    m = re.match('^(.*),LS[RL]#[0-9]+$', opnd.text)
    if m:
        reg = m.group(1)
        if reg in all_regs:
            reg_set |= set([reg])
        elif reg in all_user_regs:
            reg_set |= set([reg_names_dict[reg]])
        
    
    global _reg_blacklist
    reg_set -= _reg_blacklist
    
    reg_set = get_basic_regs(ea, reg_set)
    
    return reg_set
    
    
###########################
### Per processor funcs ###
###########################

    
############################
### Per processor values ###
############################
    
# Some registers it doesn't make sense to follow - such as the stack pointer
# This will contain a set of these registers.
# example: _reg_blacklist.add('sp')
_reg_blacklist = set()


# For a call function, this will contain the list of registers it does NOT change        
# example: _calls_with_regs['call'] = ['r3', 'r4']
_calls_with_regs = {}

# For a call function, this will contain a function, returning the op for the relevent register.
# The function signature will be: 'func(ea, reg)'
#       ea - the calling line address
#       reg - register for which we need to find the op
#
# example: _calls_with_funcs['call2'] = _call2_op
_calls_with_funcs = {}
    
           
# Some opcodes are not marked correctly (in IDA) regarding which operands are loaded or stored by them.
# This dictionary contains a tuple of lists of idxs for operands doing read and write.
# The key consists of the opcode mnemonic, and the number of params (because there is a difference between 'add r1, r2, r3' and 'add r1, r2')
# The tuple contains two fields:
#       1st field - list of idxs with read registers
#       2nd field - list of idxs with write registers
# example: _op_details_l[('load_imm',2)] = ([], [0])
# OR
# The dictionary may contain a function, returning the same tuple, or None if it decides not to handle the opcode.
# The function signature will be: 'func(ea)'
#       ea - the address of the opcode
# example: _op_details_l[('mul',2)] = mul_func
_op_details_l = {}
_op_details_l[('MOVT', 2)] = ([0], [0])
_op_details_l[('ADD', 3)] = ([0,1,2], [0])


    

######################
### Exported funcs ###
######################

# get registers used in line - a set of basic regs
def get_basic_regs(ea, reg_set):
    # For functions like 'mul r0, r2' which may change r1, add handling here.
    return reg_set

    
# is the register changed in this line    
def is_store(ea, reg):
    st_arr = []
    insn = sark.Line(ea).insn
    
    #special handling for call - may use or change registers
    if _is_call(ea):
        return ('w' in _call_op(ea, reg))
        
    global _op_details
    if _op_details(insn.mnem, len(insn.operands), ea) is not None:
        _, st_arr = _op_details(insn.mnem, len(insn.operands), ea)
    else:    
        for op in insn.operands:
            if op.type.is_reg and op.is_write:
                st_arr += [op.n]
    
    reg_set = set()
    for i in st_arr:
        if i>=len(insn.operands):
            raise ValueError('idx out of operand range', ea, i)
            
        reg_set |= _get_regs_in_operand(ea, i)    

    if reg in reg_set:
        return True
    else:
        return False

# is the register data used in this line
def is_load(ea, reg):
    ld_arr = []
    insn = sark.Line(ea).insn
  
    #special handling for call - may use or change registers
    if _is_call(ea):
        return ('r' in _call_op(ea, reg))
        
    global _op_details
    if _op_details(insn.mnem, len(insn.operands), ea) is not None:
        ld_arr, _ = _op_details(insn.mnem, len(insn.operands), ea)
    else:
        for op in insn.operands:
            if op.is_read:
                ld_arr += [op.n]            
            # a write to [a4]4 is actually a read of a4
            elif op.is_write and (not op.type.is_reg):
                ld_arr += [op.n]
            
  

    reg_set = set()
    for i in ld_arr:
        if i>=len(insn.operands):
            raise ValueError('idx out of operand range', ea, i)
                 
        reg_set |= _get_regs_in_operand(ea, i)    


    if reg in reg_set:
        return True
    else:
        return False

