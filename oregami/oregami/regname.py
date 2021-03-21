import sark
import re
import idc
import oregami_gen
from oregami_gen import debug
import ida_frame
import ida_funcs
 
######################               
#### Rename logic ####
######################

#TODOS:
# - If register is used both as load and store (like 'add d5, 5'), may want to somehow mark it as both prev
#       name and new one. Perhaps by putting a comment.
# - if blocks may be consecutive, do only one rename - Done.
# - Add functionality to define as type for all references
# - Add check if rename failed
    
def rename_reg(ea, reg, reg_new_name):
    rgs = get_block_ranges(ea, reg)
    for s_ea, e_ea in rgs:
        _rename_reg_in_range(s_ea, e_ea, reg, reg_new_name)
        
def _erase_reg_in_range(s_ea, e_ea, reg):
    pfn = ida_funcs.get_func(s_ea)
    
    ea = s_ea
    prev_ranges = []
    
    #if there was a rename range with this reg containing the start of the range (s_ea) - remember it
    prev_range_s = ida_frame.find_regvar(pfn, s_ea, reg)
    if (prev_range_s is not None) and (prev_range_s.startEA < s_ea):
        prev_ranges += [(prev_range_s.startEA, s_ea, prev_range_s.user)]

    #if there was a rename range with this reg containing the end of the range (e_ea) - remember it
    prev_range_s = ida_frame.find_regvar(pfn, e_ea, reg)
    if (prev_range_s is not None) and (prev_range_s.startEA < e_ea) and (prev_range_s.endEA > e_ea):
        prev_ranges += [(e_ea, prev_range_s.endEA, prev_range_s.user)]
        
        
    debug('Delete range %x : %x - %s' % (s_ea, e_ea, reg))
    #deletion seems to require actual existing range - so we'll change the name to orig, and then delete it
    idc.MakeLocal(s_ea, e_ea, reg, reg)
    idc.Refresh()    
    ida_frame.del_regvar(pfn, s_ea, e_ea, reg)
    idc.Refresh()
    
    #restore ranges
    for s_ea, e_ea, reg_new_name in prev_ranges:
        debug('Restore range %x : %x - %s->%s' % (s_ea, e_ea, reg, reg_new_name))
        idc.MakeLocal(s_ea, e_ea, reg, reg_new_name)
        idc.Refresh()
    
def _rename_reg_in_range(s_ea, e_ea, reg, reg_new_name):
    if (reg_new_name == reg) or (reg_new_name == ''):
        _erase_reg_in_range(s_ea, e_ea, reg)
    else:    
        _erase_reg_in_range(s_ea, e_ea, reg)
        debug('Renaming range %x : %x - %s->%s' % (s_ea, e_ea, reg, reg_new_name))
        idc.MakeLocal(s_ea, e_ea, reg, reg_new_name)
        idc.Refresh()

def get_block_ranges(ea, reg):
    found_lines, found_breaks, found_outbreaks = oregami_gen.get_refs(ea, reg)
    #eas = list(set(found_lines.keys()) - set(found_breaks.keys()))
    eas = found_lines.keys()
    rgs = _get_block_ranges(eas, reg)
    rgs = _get_min_block_ranges(rgs, reg)
    #for s,e in rgs:
    #    print '%x:%x' % (s,e)
    return rgs
    
#If between blocks there is no bad usage - make one large range    
def _get_min_block_ranges(rgs, reg):  
    if len(rgs)==0:
        return rgs

        
    debug('Ranges before:')
    for s,e in rgs:
        debug('\t%x:%x' % (s,e))
        
    rgs_d = {}
    rgs_new = []
    rgs_new2 = []
    #assumption - rgs is sorted
    s_first_blk, _ = rgs[0]
    func_start = sark.Function(s_first_blk).startEA
    
        
    #if range between ranges (or between function start and first range) doesn't contain the reg - add it as range
    curr_s = func_start
    for s_blk, e_blk in rgs:
        dontextend = False
        for l in sark.lines(curr_s, s_blk):
            if (oregami_gen.proc_ops.is_load(l.ea, reg) or oregami_gen.proc_ops.is_store(l.ea, reg)): #reg was used in line - range cannot include this
                dontextend = True
                break
                
        if not dontextend:
            rgs_new += [(curr_s, s_blk)]
            
        rgs_new += [(s_blk, e_blk)]
        curr_s = e_blk
        
    #if ranges are right after each other - make them one range
    while len(rgs_new)>0:
        #print rgs_new
        s_blk, e_blk = rgs_new[0]
        rgs_new = rgs_new[1:]
        
        #while next ranges are consecutive, eat them up
        while len(rgs_new)>0:
            s_blk2, e_blk2 = rgs_new[0]
            if e_blk!=s_blk2:
                break

            e_blk = e_blk2
            rgs_new = rgs_new[1:]
        
        rgs_new2 += [(s_blk, e_blk)]
    
    debug('Ranges after:')
    for s,e in rgs_new2:
        debug('\t%x:%x' % (s,e))
        
    return rgs_new2

def _get_block_ranges(eas, reg):
    ranges = []
    blks = set()
    for ea in eas:
        blk_ea = sark.CodeBlock(ea).startEA
        blks |= set([blk_ea])
            
    #for blk_ea in blks:
    for blk_ea in sorted(list(blks)):
        # four possible ranges:
        # 1. start till change
        # 2. change till end
        # 3. change till change - in case all references are in one block
        # 4. start till end
        # notice that 1,2 may both happen in a block
        possibility_one__found_ref = False
        possibility_one_two__found_change = False
        possibility_one__first_change_ea = None
        possibility_two__last_change_ea = None
        possibility_two__ref_after_last_change_ea = None
        possibility_three__first_ref_after_change_ea = None
        possibility_three__first_change_after_ref_ea = None
        possibility_four__no_change = True
        s_addr = None
        blk = sark.CodeBlock(blk_ea)
        for l in blk.lines:
            if (l.ea in eas): #needs to be in range
                if possibility_one_two__found_change and (possibility_two__ref_after_last_change_ea is None):
                    possibility_two__ref_after_last_change_ea = l.ea
                    
                if (possibility_one_two__found_change) and (possibility_three__first_change_after_ref_ea is None) and (possibility_three__first_ref_after_change_ea is None):
                    possibility_three__first_ref_after_change_ea = l.ea
                    
                possibility_one__found_ref = True

                
            #elif (l.ea not in eas) and (reg in oregami_gen.proc_ops.get_regs(l.ea)): #needs to be not in range                
            elif (l.ea not in eas) and (oregami_gen.proc_ops.is_load(l.ea, reg) or oregami_gen.proc_ops.is_store(l.ea, reg)): #needs to be not in range                
                if (not possibility_one_two__found_change) and (possibility_one__found_ref):
                    possibility_one__first_change_ea = l.ea
                    
                if (possibility_three__first_ref_after_change_ea is not None) and (possibility_three__first_change_after_ref_ea is None):
                    possibility_three__first_change_after_ref_ea = l.ea
                
                possibility_two__ref_after_last_change_ea = None
                possibility_one_two__found_change = True
                possibility_four__no_change = False
                

            
        # possibility 1 - found change after only references
        if possibility_one__first_change_ea is not None:            
            ranges += [(blk.startEA, possibility_one__first_change_ea)]
            debug('p1: %x:%x' % (ranges[-1][0], ranges[-1][1]))
                    
        # possibility 2 - found only references after change    
        if possibility_two__ref_after_last_change_ea is not None:
            ranges += [(possibility_two__ref_after_last_change_ea, blk.endEA)]
            debug('p2: %x:%x' % (ranges[-1][0], ranges[-1][1]))

        # possibility 3 - found sequrence change->ref->change
        if (possibility_three__first_ref_after_change_ea is not None) and (possibility_three__first_change_after_ref_ea is not None):
            ranges += [(possibility_three__first_ref_after_change_ea, possibility_three__first_change_after_ref_ea)]
            debug('p3: %x:%x' % (ranges[-1][0], ranges[-1][1]))
        
        # possibility 4 - no change happened
        if possibility_four__no_change:
            ranges += [(blk.startEA, blk.endEA)]
            debug('p4: %x:%x' % (ranges[-1][0], ranges[-1][1]))
            

    return ranges
    
    
    
###########
## debug ##
###########



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
    