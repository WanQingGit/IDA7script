import idaapi
import sark

from oregami.oregami_forms import oregamiPluginStarter, supported_procs

#import here - so that the libraries won't print that annoying 'Note: FormToPyQtWidget: importing XXX module into <module '__main__' from ''>'
from PyQt5 import QtWidgets
import sip


class OregamiWindow(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "oREGami"
    help = "Find references to register in function"
    wanted_name = "OregamiWindow"
    wanted_hotkey = "Shift+X"

    def init(self):
        self._prev_struct_name = ""
        
        proc_name = sark.idaapi.get_inf_structure().procName
        if proc_name not in supported_procs:
            print 'Oregami plugin: No full support for this processor. Will do our best :)'
            #return idaapi.PLUGIN_SKIP

        return idaapi.PLUGIN_OK
        
    def term(self):
        pass

    def run(self, arg):
        print arg
        start, _ = sark.get_selection()

        oregamiPluginStarter(start, tabMode=False, recursive_bool=False)
        

def PLUGIN_ENTRY():
    return OregamiWindow()
