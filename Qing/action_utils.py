from Qing.common import Debugger
from Qing import common
import re
from Qing.hexrays_utils import *
from Qing.struct_utils import st_rename_auto


# from collections import defaultdict
class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "ActionTool:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError


# regs=idaapi.dbg_get_registers() #[('X0', 16, 1, 7, None, 0),
dbg_action = Debugger()
dbg_action.off()
dbg_action()


class PopupAction(Action):

    def activate(self, ctx):
        raise NotImplementedError

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

    def __init__(self):
        # Action.__init__(self)
        super(Action, self).__init__()

    def check(self, hx_view):
        # type: (idaapi.vdui_t) -> bool
        raise NotImplementedError


class StructRename(PopupAction):
    description = "Rename struct auto"

    def __init__(self):
        super(PopupAction, self).__init__()
        self.st = None

    def activate(self, ctx):
        st_rename_auto(self.st)

    def check(self, hx_view):
        cfunc, ctree_item = hx_view.cfunc, hx_view.item
        if isinstance(ctree_item, idaapi.ctree_item_t):
            lvar = ctree_item.get_lvar()
            if lvar:
                typestr = common.get_typestr(lvar.tif)
                t = re.sub("(P+)|(A\d+)$", "", typestr, 1)
                if t not in common.basec:
                    tid = idaapi.get_struc_id(t)
                    st = idaapi.get_struc(tid)
                    if st:
                        self.st = st
                        return st
                    else:
                        return None
            # if arg.citype != idaapi.VDI_EXPR:
            #     return None
            else:
                return None


class TestAction(Action):
    description = "Rename local vars"

    def __init__(self):
        super(TestAction, self).__init__()

    def activate(self, ctx):  # type: (idaapi.action_activation_ctx_t) -> None
        return
        dbg_action()
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        names = {}
        cfunc = hx_view.cfunc
        lvars = cfunc.lvars
        for i in range(lvars.size()):
            addsuffix = True
            var = lvars[i]
            # dbg_action.info(typestr)
            width = var.width
            dbg_action.info(
                "assert {} var.width==tif.get_size() {}".format(var.tif.dstr().strip(), var.tif.get_size() == width))
            location = var.location
            if var.is_arg_var:
                name = var.name.split("_")[0]
            elif location.is_reg():
                reg = (location.get_reginfo() >> 3) - 1
                if reg == -1:
                    name = "zf"
                elif reg >= 41:
                    addsuffix = False
                    name = "s" + str((reg - 41) / 2)
                elif width == 8:
                    name = 'x' + str(reg)
                else:
                    name = 'w' + str(reg)
            else:
                ea = location.get_ea()
                name = 's' + ("%x" % ea).upper()
            if addsuffix:
                name_suffix = common.get_typestr(var.tif)
                if re.search("\(.+\)\(.*\)$", name_suffix):
                    name += "_" + "fn"
                else:
                    name += "_" + name_suffix

            if name in names:
                suffix = names[name]
                names[name] = suffix + 1
                name = name + "_" + str(suffix)
            else:
                names[name] = 1
            if var.name != name:
                hx_view.rename_lvar(var, name, True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


def action_reg(action):
    idaapi.action_desc_t(action.name, action.description, action, action.hotkey)

# if self.__action.check(hx_view):
#         idaapi.attach_action_to_popup(form, popup, self.__action.name, None)
# return 0
# idaapi.register_action(
#     idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
# )
