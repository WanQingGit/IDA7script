from Qing.common import *
from Qing import action_utils
import idaapi

hexrays_arg = None
hexrays_hk = None
# HL_COLOR = 0xAD8044
HL_COLOR = 0x66ff99
DEF_COLOR = 0xffffffff


def get_item_indexes(line):
    indexes = []
    tag = idaapi.COLOR_ON + chr(idaapi.COLOR_ADDR)
    pos = line.find(tag)
    while pos != -1 and len(line[pos + len(tag):]) >= idaapi.COLOR_ADDR_SIZE:
        item_idx = line[pos + len(tag):pos + len(tag) + idaapi.COLOR_ADDR_SIZE]
        indexes.append(int(item_idx, 16))
        pos = line.find(tag, pos + len(tag) + idaapi.COLOR_ADDR_SIZE)
    return indexes


class HexraysHook(object):

    def __init__(self, sync=True):
        self.sync = sync
        self.actions = []
        self.popactions = []
        self.pseudocode_instances = {}
        self.__handle = self.handle
        self.install()

    def install(self):
        idaapi.install_hexrays_callback(self.__handle)

    def register(self, action):
        idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )
        if isinstance(action, action_utils.PopupAction):
            self.popactions.append(action)
        else:
            self.actions.append(action)

    def reset_colors(self, idx, ignore_vd=False):
        v = self.pseudocode_instances[idx]
        if v:
            pseudocode, lineno, color, disasm_lines = v
            if not ignore_vd and pseudocode:
                try:
                    if color != HL_COLOR:
                        pseudocode[lineno].bgcolor = color
                    else:
                        pseudocode[lineno].bgcolor = DEF_COLOR
                except Exception as  e:  # wtf
                    print(e)
            for ea, color in disasm_lines:
                if color != HL_COLOR:
                    idaapi.set_item_color(ea, color)
                else:
                    idaapi.set_item_color(ea, DEF_COLOR)
        # pseudocode_instances.pop(idx)
        return

    def reset_all_colors(self, ignore_vd=False):
        pseudocode_instances = self.pseudocode_instances
        # restore colors
        if pseudocode_instances:
            for k, _ in pseudocode_instances.iteritems():
                self.reset_colors(k, ignore_vd)
            pseudocode_instances.clear()
        return

    def apply_colors(self, vd, result):
        self.reset_all_colors()
        if not result:
            return
        pseudocode, lineno, col, item_ea_list = result
        disasm_lines = [(ea, idaapi.get_item_color(ea)) for ea in item_ea_list]
        if len(item_ea_list):
            idaapi.jumpto(item_ea_list[0], -1, idaapi.UIJMP_IDAVIEW | idaapi.UIJMP_DONTPUSH)
        self.pseudocode_instances[vd.view_idx] = (pseudocode, lineno, col, disasm_lines)

        if pseudocode:
            try:
                pseudocode[lineno].bgcolor = HL_COLOR
            except Exception as err:  # wtf
                print(err)
        for ea, _ in disasm_lines:
            idaapi.set_item_color(ea, HL_COLOR)

    def uninstall(self):
        self.reset_all_colors()
        idaapi.remove_hexrays_callback(self.__handle)
        for action in self.actions:
            idaapi.unregister_action(action.name)
        for action in self.popactions:
            idaapi.unregister_action(action.name)
        self.actions = []
        self.popactions = []

    def handle(self, event, *args):
        _dbg.info("hexrays callback ", event, args)
        global hexrays_arg
        hexrays_arg = args
        _dbg()
        if event == idaapi.hxe_populating_popup:
            form, popup, hx_view = args
            for action in self.actions:
                idaapi.attach_action_to_popup(form, popup, action.name, None)
            for action in self.popactions:
                if action.check(hx_view):
                    idaapi.attach_action_to_popup(form, popup, action.name, None)
            return 0
        elif event != idaapi.hxe_double_click:  # 106,idaapi.hxe_right_click 105
            return 0
        if not self.sync:
            return 0
        vd = args[0]
        try:
            lineno = vd.cpos.lnnum
            pseudocode = vd.cfunc.get_pseudocode()
            if pseudocode and lineno != -1:
                color = pseudocode[lineno].bgcolor
                view_idx = vd.view_idx
                if color == HL_COLOR and view_idx in self.pseudocode_instances:
                    self.reset_colors(view_idx)
                    self.pseudocode_instances.pop(view_idx)
                    return 0
                line = pseudocode[lineno].line
                item_idxs = get_item_indexes(line)
                ea_list = set()
                for i in item_idxs:
                    try:
                        item = vd.cfunc.treeitems.at(i)
                        if item and item.ea != idaapi.BADADDR:
                            ea_list.add(item.ea)
                            # ea_list[item.ea] = None
                    except:
                        pass
                self.apply_colors(vd, (pseudocode, lineno, color, sorted(ea_list)))
        except Exception as err:
            self.reset_all_colors()
            print(err)
        return 0


_dbg = Debugger(trace=False, level=DBG_WARN)
_dbg.on()
_dbg()


# -----------------------------------------------------------------------
class HexraysPlugin(idaapi.plugin_t):
    comment = ''
    help = ''
    flags = idaapi.PLUGIN_MOD
    wanted_name = 'hexrays tools'
    wanted_hotkey = 'Ctrl-Shift-S'
    hxehook = None

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if not HexraysPlugin.hxehook:
            HexraysPlugin.hxehook = HexraysHook()
            HexraysPlugin.hxehook.register(action_utils.TestAction())
            HexraysPlugin.hxehook.register(action_utils.StructRename())
        else:
            HexraysPlugin.hxehook.uninstall()
            HexraysPlugin.hxehook = None
        idaapi.msg("[+] %s is %sabled now.\n" % (HexraysPlugin.wanted_name, "en" if HexraysPlugin.hxehook else "dis"))

    def term(self):
        idaapi.msg("[+] %s unloaded.\n" % HexraysPlugin.wanted_name)
        hexhook = HexraysPlugin.hxehook
        if hexhook:
            hexhook.uninstall()
            HexraysPlugin.hxehook = None


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return HexraysPlugin()


_dbg()
if "SCRIPT_LOAD" in dir():
    try:
        if hexrays_hk:
            hexrays_hk.uninstall()
            print("remove previous hexrays_hk")
        reload(action_utils)
        raise Exception("Init hook...")
    except:
        hexrays_hk = HexraysHook(sync=True)
        hexrays_hk.register(action_utils.TestAction())
        hexrays_hk.register(action_utils.StructRename())

# idaapi.install_hexrays_callback(hexrays_hk)
# cfunc.arguments
# vars.size()
# hx_view.rename_lvar(lvar, name, True)
# v.tif.dstr()
