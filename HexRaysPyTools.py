import logging

import idaapi

import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
from HexRaysPyTools.callbacks import hx_callback_manager, action_manager
from HexRaysPyTools.core.struct_xrefs import XrefStorage
from HexRaysPyTools.core.temporary_structure import TemporaryStructureModel



class MyPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "See https://github.com/igogo-x86/HexRaysPyTools/blob/master/readme.md"
    wanted_name = "HexRaysPyTools"
    wanted_hotkey = ""
    load = None

    @staticmethod
    def init():
        if not idaapi.init_hexrays_plugin():
            logging.error("Failed to initialize Hex-Rays SDK")
            return idaapi.PLUGIN_SKIP

        action_manager.initialize()
        hx_callback_manager.initialize()
        cache.temporary_structure = TemporaryStructureModel()
        const.init()
        XrefStorage().open()
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run():
        pass

    @staticmethod
    def term():
        action_manager.finalize()
        hx_callback_manager.finalize()
        XrefStorage().close()
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    settings.load_settings()
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(settings.DEBUG_MESSAGE_LEVEL)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    return MyPlugin()

# from Qing.common import Debugger
# _hexray_dbg=Debugger()
# _hexray_dbg()
if "SCRIPT_LOAD" in dir():
    if MyPlugin.load:
        MyPlugin.term()
    MyPlugin.init()
    MyPlugin.load = True
