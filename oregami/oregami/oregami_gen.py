import sark
import re
import idc
import ida_kernwin
import idautils
import md5
import struct


#TODOS:
#- Maybe if sequence of lines change reg, handle all as one var. Call it a writers block :P - Done.
#- make this return two dictionaries, with breaks already here - Done.
#- refs in block should return another dictionary of the breaks not in the frame (outbreaks) - Done.
#- Should contain reads that are breaks - Done.
#- make is_load, is_store handle funcs by default - Done.
#- Add some hash of current function flow to the cacheing - so that if the function changes, we will recalculate refs - Done.
#- Add reverse if got to start of func (or no back references) - Done.
#- if line is rw, do both forward and back scan
#- Add same logic for stack variables (that are sometimes reused)
#- add to cache only if took more than X time
#- make cache work as lru system
#- Changed usage to not use the should_stop api of processor. Update to include call fucntionality in generic way
#- sark problem with CodeBlock on non code - add check that in code
#- In _op_details_l, use actual opcode and not the short version. Perhaps add the number of operands as part of the name.


import ppc_oregami as ppc_oregami_ops
import arm_oregami as arm_oregami_ops
import def_oregami as def_oregami_ops

_proc_libs = {}
_proc_libs['PPC'] = ppc_oregami_ops
_proc_libs['ARM'] = arm_oregami_ops

_proc_name = sark.idaapi.get_inf_structure().procName

if _proc_name in _proc_libs:
    proc_ops = _proc_libs[_proc_name]
else:
    proc_ops = def_oregami_ops
    
    #raise "Unsupported Processor for oregami"

supported_procs = _proc_libs.keys()

BK = 0
FW = 1
ST = 2 #start
    
####################                  
#### Scan logic ####
####################

# get refs for multiple registers
def get_refs_multiple(ea):
    reg = get_cursor_reg(ea)
    
    if reg is None:
        return {}
        
    reg_set = set([reg])
    
    regs = proc_ops.get_basic_regs(ea, reg_set)
    ret_dict = {}
    for reg in regs:
        print 'Find refs for %s..' % reg
        found_lines, found_breaks, _ = get_refs(ea, reg)
        ret_dict[reg] = {}
        ret_dict[reg].update(found_lines)
        ret_dict[reg].update(found_breaks)
            
    return ret_dict

    
# get refs for single register - from cache if exists
_CACHED_REFS_NUM = 20
_cached_idx = 0
_cached_addr = {}
_cached_refs = {}


def get_func_hash(ea):
    m = md5.new()
    ea = sark.Function(ea).start_ea
    blk = sark.CodeBlock(ea)
    went_over_blks = set()
    rem_blks = [blk]
    
    while len(rem_blks):
        blk = rem_blks[0]
        rem_blks = rem_blks[1:]
        m.update('s')
        m.update(struct.pack(">L", blk.start_ea))
        for n_blk in blk.next:
            m.update(struct.pack(">L", n_blk.start_ea))
            if n_blk.start_ea not in went_over_blks:
                rem_blks += [n_blk]
        went_over_blks.add(blk.start_ea)
    return m.digest()

        
    
        
    

# get refs for reg. Including cache system
def get_refs(ea=None, reg='d15', do_print=False):
    global _cached_idx
    global _cached_addr
    global _cached_refs
    
    if ea is None:
        ea = get_screen_ea()
            
    ea = sark.Line(ea).ea #get ea that is start of line       
    func_hash = get_func_hash(ea)
    
    for i in _cached_addr.keys():
        c_reg, c_lines_set, c_func_hash = _cached_addr[i]     
        #print c_reg
        #print c_ea_list
        if c_func_hash==func_hash and c_reg==reg and (ea in c_lines_set):
            print 'Found cached for %s in %x' % (reg, ea)
            return _cached_refs[i]
        
    #print 'cache idx = %d' % _cached_idx
    _cached_refs[_cached_idx] = _get_refs(ea, reg, do_print)

    found_lines, found_breaks, found_outbreaks = _cached_refs[_cached_idx]
    #lines_set = set(found_lines.keys()) - set(found_breaks.keys())
    lines_set = set(found_lines.keys())
    
    #if input ea doesnt contain the register, add it explicitly
    lines_set.add(ea)
    
    _cached_addr[_cached_idx] = (reg, lines_set, func_hash)
    ret_val = _cached_refs[_cached_idx]
    
    _cached_idx += 1
    if _cached_idx >= _CACHED_REFS_NUM:
        _cached_idx = 0
        
    return ret_val    
        
    


# get refs for single register 
# returns tuple with (found_lines, found_breaks)   
def _get_refs(ea=None, reg='d15', do_print=False):
    if ea is None:
        ea = get_screen_ea()
            
    debug('Start search - ea=%x, reg=%s' % (ea, reg))
    ea = sark.Line(ea).ea #get ea that is start of line       
    
    fw_set = {}
    bw_set = {}
    
    blk = CodeBlock(ea)
    
    found_lines = {}
    found_breaks = {}
    found_outbreaks = {}
    remaining_blks = []
    used_blks = set()
    
    # check curr
    op = ''
    if proc_ops.is_load(ea, reg):
        debug('Start is load')
        op += 'r'
    if proc_ops.is_store(ea, reg):
        debug('Start is store')
        op += 'w'
        
    if op!='':        
        found_lines[ea] = op
        
    # go forward
    initstage = ('w' in op)
    
    fw_found_lines, fw_found_breaks, fw_found_outbreaks, fw_stop, fw_initstage = get_refs_blk(ea_next(ea), blk.start_ea, FW, initstage, reg)
    found_lines.update(fw_found_lines)
    found_breaks.update(fw_found_breaks)
    found_outbreaks.update(fw_found_outbreaks)
    
    if not fw_stop:
        for n_blk in blk.next:
            debug('added start: %x, %s' % (n_blk.start_ea, ['bk', 'fw'][FW]))
            remaining_blks += [(FW, fw_initstage, n_blk.start_ea)]
                
    
    #go backwards - only if reg is not a STOP op in current ea
    stop = (op=='w')
    
    if not stop:
        bk_found_lines, bk_found_breaks, bk_found_outbreaks, bk_stop, bk_initstage = get_refs_blk(ea, blk.start_ea, BK, initstage, reg)
        
        found_lines.update(bk_found_lines)
        found_breaks.update(bk_found_breaks)
        found_outbreaks.update(bk_found_outbreaks)
        if not bk_stop:
            for p_blk in blk.prev:
                debug('added start: %x, %s' % (p_blk.start_ea, ['bk', 'fw'][BK]))
                remaining_blks += [(BK, bk_initstage, p_blk.start_ea)]
         
        
    #go over blks - until there are no more
    while len(remaining_blks)>0:
        dir, initstage, blk_ea = remaining_blks[0]
        debug('parsing: %x, %s' % (blk_ea, ['bk', 'fw'][dir]))
                
        remaining_blks = remaining_blks[1:]
        
        blk = CodeBlock(blk_ea)
        if dir==FW:
            first_ea = blk.start_ea
        elif dir==BK:
            first_ea = blk.end_ea
                    
        blk_found_lines, blk_found_breaks, blk_found_outbreaks, blk_stop, blk_initstage = get_refs_blk(first_ea, blk_ea, dir, initstage, reg)
        found_lines.update(blk_found_lines)
        found_breaks.update(blk_found_breaks)
        found_outbreaks.update(blk_found_outbreaks)
        
        should_rev = False

        if len(blk_found_lines)>0 or len(blk_found_breaks)>0:
            should_rev = True
            debug('found lines in blk. reversing')
        #if we are going backwards in first block of function, and there was no usage or reason to stop
        elif dir==BK and blk.start_ea==sark.Function(blk.start_ea).start_ea: # and not blk_stop:
            should_rev = True
            debug('first block. reversing')
            
        #if we found loads -> add reverse direction for block, and use same initstage used for this block
        if should_rev:
            if dir==FW:
                blks = blk.prev
            elif dir==BK:
                blks = blk.next
                
            for e_blk in blks:
                if (1-dir, e_blk.start_ea) not in used_blks:
                    debug('added (rev): %x, %s' % (e_blk.start_ea, ['bk', 'fw'][1-dir]))
                    used_blks.add((1-dir, e_blk.start_ea))
                    remaining_blks += [(1-dir, initstage, e_blk.start_ea)]
        
        #if didn't stop -> add blocks in same direction, and use new initstage
        if not blk_stop:
            if dir==FW:
                blks = blk.next
            elif dir==BK:
                blks = blk.prev
                
            for e_blk in blks:
                if (dir, e_blk.start_ea) not in used_blks:
                    debug('added (same): %x, %s' % (e_blk.start_ea, ['bk', 'fw'][dir]))
                    used_blks.add((dir, e_blk.start_ea))
                    remaining_blks += [(dir, blk_initstage, e_blk.start_ea)]

         

    #sometimes a break from one direction, is a found line from another direction. Update breaks so they wont contain found lines
    for ea in (set(found_lines.keys()) & set(found_outbreaks.keys())):
        #print 'not supposed to happen'
        #raise
        del found_outbreaks[ea]
    
    for ea in sorted(found_lines.keys()):
        op = found_lines[ea]
        debug('Found line: [%s] %x ' % (op, ea))
        
    for ea in sorted(found_breaks.keys()):
        op = found_breaks[ea]
        debug('Found break: [%s] %x ' % (op, ea))
        
    for ea in sorted(found_outbreaks.keys()):
        op = found_outbreaks[ea]
        debug('Found out-break: [%s] %x ' % (op, ea))
        

    return found_lines, found_breaks, found_outbreaks
  
    
# scan from ea forward or backwards till stop, or till edge of block
def get_refs_blk(ea, blk_ea, dir, initstage, reg):
    superdebug = False
    if blk_ea==0x801e7788:
        superdebug = True
        print 'Entered SUPER'

    blk = CodeBlock(blk_ea)
    if dir==FW:
        lines = sark.lines(start=ea, end=blk.end_ea)
    elif dir==BK:
        lines = sark.lines(start=blk.start_ea, end=ea, reverse=True)

    found_lines = {}
    found_breaks = {}
    found_outbreaks = {}
        
    stop = False
    for l in lines:
        if superdebug:
            print 'SUPER: %x' % l.ea
            
        if stop:
            break
            
        op = ''
        if proc_ops.is_load(l.ea, reg):
            op += 'r'
        if proc_ops.is_store(l.ea, reg):
            op += 'w'
            
        if op=='':
            continue
            
        if dir==FW:
            if op=='r':
                initstage = False
            elif op=='w':
                #found_breaks[l.ea] = op
                found_outbreaks[l.ea] = op
                stop = True
                break
            elif op=='rw':
                if not initstage:
                    found_breaks[l.ea] = op
                    stop = True
                    break
        elif dir==BK:            
            if op=='r':
                if initstage:
                    #found_breaks[l.ea] = op
                    found_outbreaks[l.ea] = op
                    stop = True
                    break
            elif op=='w':
                initstage = False
                stop = True
            elif op=='rw':
                initstage = True
                    
                    
        found_lines[l.ea] = op        
        
    return found_lines, found_breaks, found_outbreaks, stop, initstage

   
   
#################################
### Sark fixes and extensions ###
#################################    

def ea_next(ea):
    return sark.Line(ea).end_ea
    
#fix a bug where sometimes blocks are outside the function    
def CodeBlock(ea):
    cb = sark.CodeBlock(ea)
    #fix next and prev blocks - must be in func
    next = []
    prev = []
    for e_cb in cb.next:
        if sark.Function(e_cb.start_ea).start_ea == sark.Function(cb.start_ea).start_ea:
            next += [e_cb]
    for e_cb in cb.prev:
        if sark.Function(e_cb.start_ea).start_ea == sark.Function(cb.start_ea).start_ea:
            prev += [e_cb]
        
    class new_cb(object):
        pass
    
    ncb = new_cb()
    ncb.start_ea = cb.start_ea
    ncb.end_ea = cb.end_ea
    ncb.next = next
    ncb.prev = prev
    return ncb

    
###########
## debug ##
###########

def debug(s):
    #return
    print s
    
#########################
### Reg functionality ###
#########################

#get the register that the cursor is on
def get_cursor_reg(ea):
    #print 'get_cursor_reg'
    
    if 'get_highlight' in dir(ida_kernwin): #in IDA 7.1
        w = ida_kernwin.get_current_viewer()
        t = ida_kernwin.get_highlight(w)
        reg = None
        if t:
            reg, _ = t
    else: #in IDA 6.98
        reg = ida_kernwin.get_highlighted_identifier()
        
    if reg is None:
        return None
    reg = get_reg_canon_name(ea, reg)
    if reg in idautils.GetRegisterList():
        return reg
    return None
    
#if reg was renamed - get full name 
def get_reg_full_name(ea, reg):
    if reg not in get_reg_canon_to_user(ea):
        return reg
        
    return '%s {%s}' % (get_reg_canon_to_user(ea)[reg], reg)

#get user given reg_name if exists    
def get_reg_user_name(ea, reg):
    if reg not in get_reg_canon_to_user(ea):
        return reg
        
    return get_reg_canon_to_user(ea)[reg]
    
#get canon reg_name if exists    
def get_reg_canon_name(ea, reg):
    if reg not in get_reg_user_to_canon(ea):
        return reg
        
    return get_reg_user_to_canon(ea)[reg]
    
    
#returns mapping of user_given_reg_name to register name
def get_reg_user_to_canon(ea=None):
    from idautils import GetRegisterList
    from ida_frame import find_regvar
    from ida_funcs import get_func
    
    if ea is None:
        ea = idc.get_screen_ea()

    d = {}

    for canon in GetRegisterList():
        regvar = find_regvar(get_func(ea), ea, canon)
        if regvar:
            #d[canon] = regvar.user
            d[regvar.user] = canon
            
    return d    

#returns mapping of register name to user_given_reg_name
def get_reg_canon_to_user(ea):
    from idautils import GetRegisterList
    from ida_frame import find_regvar
    from ida_funcs import get_func
    
    d = {}

    for canon in GetRegisterList():
        regvar = find_regvar(get_func(ea), ea, canon)
        if regvar:
            d[canon] = regvar.user
            
    return d  
    
