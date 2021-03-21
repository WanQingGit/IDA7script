import  idaapi

SO_LOCAL_VARIABLE = 1       # cexpr.op == idaapi.cot_var
SO_STRUCT_POINTER = 2       # cexpr.op == idaapi.cot_memptr
SO_STRUCT_REFERENCE = 3     # cexpr.op == idaapi.cot_memref
SO_GLOBAL_OBJECT = 4        # cexpr.op == idaapi.cot_obj
SO_CALL_ARGUMENT = 5        # cexpr.op == idaapi.cot_call
SO_MEMORY_ALLOCATOR = 6
SO_RETURNED_OBJECT = 7

def get_member_name(tinfo, offset):
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
    return udt_member.name

class ScanObject(object):
    def __init__(self):
        self.ea = idaapi.BADADDR
        self.name = None
        self.tinfo = None
        self.id = 0

    @staticmethod
    def create(cfunc, ctree_item):
        # Creates object suitable for scaning either from cexpr_t or ctree_item_t
        if isinstance(ctree_item, idaapi.ctree_item_t):
            lvar = ctree_item.get_lvar()
            if lvar:
                index = list(cfunc.get_lvars()).index(lvar)
                result = VariableObject(lvar, index)
                if ctree_item.e:
                    result.ea = ScanObject.get_expression_address(cfunc, ctree_item.e)
                return result
            if ctree_item.citype != idaapi.VDI_EXPR:
                return None
            cexpr = ctree_item.e
        else:
            cexpr = ctree_item

        if cexpr.op == idaapi.cot_var:
            lvar = cfunc.get_lvars()[cexpr.v.idx]
            result = VariableObject(lvar, cexpr.v.idx)
            result.ea = ScanObject.get_expression_address(cfunc, cexpr)
            return result
        elif cexpr.op == idaapi.cot_memptr:
            t = cexpr.x.type.get_pointed_object()
            result = StructPtrObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_memref:
            t = cexpr.x.type
            result = StructRefObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_obj:
            result = GlobalVariableObject(cexpr.obj_ea)
            result.name = idaapi.get_short_name(cexpr.obj_ea)
        else:
            return
        result.tinfo = cexpr.type
        result.ea = ScanObject.get_expression_address(cfunc, cexpr)
        return result

    @staticmethod
    def get_expression_address(cfunc, cexpr):
        expr = cexpr

        while expr and expr.ea == idaapi.BADADDR:
            expr = expr.to_specific_type
            expr = cfunc.body.find_parent_of(expr)

        assert expr is not None
        return expr.ea

    def __hash__(self):
        return hash((self.id, self.name))

    def __eq__(self, other):
        return self.id == other.id and self.name == other.name

    def __repr__(self):
        return self.name

class VariableObject(ScanObject):
    # Represents `var` expression
    def __init__(self, lvar, index):
        super(VariableObject, self).__init__()
        self.lvar = lvar
        self.tinfo = lvar.type()
        self.name = lvar.name
        self.index = index
        self.id = SO_LOCAL_VARIABLE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_var and cexpr.v.idx == self.index


class StructPtrObject(ScanObject):
    # Represents `x->m` expression
    def __init__(self, struct_name, offset):
        super(StructPtrObject, self).__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = SO_STRUCT_POINTER

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memptr and cexpr.m == self.offset and \
               cexpr.x.type.get_pointed_object().dstr() == self.struct_name


class StructRefObject(ScanObject):
    # Represents `x.m` expression
    def __init__(self, struct_name, offset):
        super(StructRefObject, self).__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = SO_STRUCT_REFERENCE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memref and cexpr.m == self.offset and cexpr.x.type.dstr() == self.struct_name


class GlobalVariableObject(ScanObject):
    # Represents global object
    def __init__(self, object_address):
        super(GlobalVariableObject, self).__init__()
        self.obj_ea = object_address
        self.id = SO_GLOBAL_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_obj and self.obj_ea == cexpr.obj_ea


class CallArgObject(ScanObject):
    # Represents call of a function and argument index
    def __init__(self, func_address, arg_idx):
        super(CallArgObject, self).__init__()
        self.func_ea = func_address
        self.arg_idx = arg_idx
        self.id = SO_CALL_ARGUMENT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_call and cexpr.x.obj_ea == self.func_ea

    def create_scan_obj(self, cfunc, cexpr):
        e = cexpr.a[self.arg_idx]
        while e.op in (idaapi.cot_cast, idaapi.cot_ref, idaapi.cot_add, idaapi.cot_sub, idaapi.cot_idx):
            e = e.x
        return ScanObject.create(cfunc, e)

    @staticmethod
    def create(cfunc, arg_idx):
        result = CallArgObject(cfunc.entry_ea, arg_idx)
        result.name = cfunc.get_lvars()[arg_idx].name
        result.tinfo = cfunc.type
        return result

    def __repr__(self):
        return "{}"


class ReturnedObject(ScanObject):
    # Represents value returned by function
    def __init__(self, func_address):
        super(ReturnedObject, self).__init__()
        self.__func_ea = func_address
        self.id = SO_RETURNED_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_call and cexpr.x.obj_ea == self.__func_ea


class MemoryAllocationObject(ScanObject):
    # Represents `operator new()' or `malloc'
    def __init__(self, name, size):
        super(MemoryAllocationObject, self).__init__()
        self.name = name
        self.size = size
        self.id = SO_MEMORY_ALLOCATOR

    @staticmethod
    def create(cfunc, cexpr):
        if cexpr.op == idaapi.cot_call:
            e = cexpr
        elif cexpr.op == idaapi.cot_cast and cexpr.x.op == idaapi.cot_call:
            e = cexpr.x
        else:
            return

        func_name = idaapi.get_short_name(e.x.obj_ea)
        if "malloc" in func_name or "operator new" in func_name:
            carg = e.a[0]
            if carg.op == idaapi.cot_num:
                size = carg.numval()
            else:
                size = 0
            result = MemoryAllocationObject(func_name, size)
            result.ea = ScanObject.get_expression_address(cfunc, e)
            return result