"""
Todo:
- Make the tree copyable & searchable
"""
import idaapi
import idautils
import idc
import sark
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets

from ida_kernwin import _ida_kernwin
from oregami_gen import *
import oregami_gen

supported_procs = oregami_gen.supported_procs

def _evalTargetName(ea):
    """
    Find the variable that actually contains the flags.
    The variable should be referenced to in the instruction, address of which is passed in ea
    """
    target = None
    l = sark.Line(ea)
    for xref in l.xrefs_from:
        if xref.type.name != 'Ordinary_Flow':
            # Probably it..
            target = sark.Line(xref.to)
            break

    if not target:
        return '???'

    if target.name:
        return target.name
    else:
        return '0x%08X' % target.ea

class FormManager(object):
    """
    Manages multiple simultaneous tabs (single tab per flag variable), and only a single window
    """
    windowForm = None
    tabForms = []

    @staticmethod
    def findTab(ea):
        targetName = _evalTargetName(ea)

        for tab in FormManager.tabForms:
            if tab.TabIdentifier() == targetName:
                return tab

        return None

    @staticmethod
    def openTab(ea, recursive_bool):
        tab = FormManager.findTab(ea)
        if tab:
            tab.PopulateTree(ea)
        else:
            tab = FlagBrowserPlugin(ea, tabMode=True, recursive_bool=recursive_bool)
            FormManager.tabForms.append(tab)

        tab.Show()

    @staticmethod
    def openWindow(ea, recursive_bool):
        if FormManager.windowForm:
            # Repopulate
            FormManager.windowForm.PopulateTree(ea)
        else:
            FormManager.windowForm = FlagBrowserPlugin(ea, tabMode=False, recursive_bool=recursive_bool)

        FormManager.windowForm.Show()

    @staticmethod
    def openForm(ea, tabMode, recursive_bool):
        if tabMode:
            FormManager.openTab(ea, recursive_bool)
        else:
            FormManager.openWindow(ea, recursive_bool)

    @staticmethod
    def closeForm(ea, tabMode):
        #TODO: Get ea from the plugin itself when it's closed
        if tabMode:
            tab = FormManager.findTab(ea)
            FormManager.tabForms.remove(tab)
            del tab
        else:
            del FormManager.windowForm
            FormManager.windowForm = None

    
#def flagBrowserPluginStarter(ea, tabMode=False):
def oregamiPluginStarter(ea, tabMode=False, recursive_bool=False):
    FormManager.openForm(ea, tabMode, recursive_bool)

def oregamiPluginDestructor(ea, tabMode):
    FormManager.closeForm(ea, tabMode)

class FlagBrowserPlugin(PluginForm):
    def __init__(self, ea, tabMode=False, recursive_bool=False):
        self.ea = ea
        self.tabMode = tabMode
        self.recursive_bool = recursive_bool
        self._Reset(ea)
        PluginForm.__init__(self)

    def _Reset(self, ea):
        self.ea = ea
        self.targetName = _evalTargetName(ea)

    def TabIdentifier(self):
        return self.targetName

    def ItemActivatedSlot(self, item, column):
        try:
            ea = item.flagBrowserData["ea"]
        except KeyError:
            # Not clickable
            return

        if not self.tabMode:
            # Close only window mode
            print '[*] Closing 0x%06X' % self.ea
            self.Close(PluginForm.FORM_CLOSE_LATER)

        idc.Jump(ea)

    def BuildReferences(self, ea):
        reg_dict = get_refs_multiple(ea=ea)

        return reg_dict

    def PopulateSubtree(self, ea, base_tree): 
        font = QtGui.QFont("Consolas", 10)
        #font = QtGui.QFont("8514oem", 3, QtGui.QFont.Bold)
        #font.setPointSize(0)
        reg_dict = self.BuildReferences(ea)
        orig_ea = ea
        saved_item = None
        if len(reg_dict)==0:
            print 'No reg found'
            self.Close(PluginForm.FORM_CLOSE_LATER)
        
        for reg in reg_dict.keys():
            print 'Populate %s' % reg
            if len(reg_dict[reg])==0:
                continue                

            # Build for every referenced reg
            refHeader = QtWidgets.QTreeWidgetItem(base_tree)
            refHeader.setText(0, '<%s> references [from 0x%x]' % (get_reg_full_name(orig_ea, reg), orig_ea))
            refHeader.setFont(0, font)
            
            #saved_item = refHeader


            for ea in sorted(reg_dict[reg].keys()):
                op = reg_dict[reg][ea]
                
                item = QtWidgets.QTreeWidgetItem(refHeader)
                #item = QtWidgets.QTreeWidgetItem(base_tree) #tmp
                if ea<orig_ea:
                    dir = '^'
                elif ea>orig_ea:
                    dir = 'v'
                else:
                    saved_item = item
                    
                    dir = '.'
                item.setText(0, "|%s| [%s] [0x%x] %s" % (dir, op, ea, idc.GetDisasm(ea)))
                item.setFont(0, font)
                item.flagBrowserData = {"ea": ea}

            refHeader.setExpanded(True)
            #refHeader.setFocus()
            #saved_item.Focus()
            #base_tree.setTreePosition(2)
            #base_tree.scrollToBottom()
        return saved_item

    def PopulateTree(self, ea):
        self._Reset(ea)

        # Clear previous items
        self.tree.clear()
        item = self.PopulateSubtree(ea, self.tree)
        #self.tree.resizeColumnToContents(0) #trial
        
        # Populate means we just reloaded the list of references; Let's focus the first one        
        if item is None:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item, QtWidgets.QAbstractItemView.PositionAtCenter)
            
        self.tree.setFocus()

        

    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        print '[*] OnCreate 0x%06X' % self.ea

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)


        # Create tree control
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Reg References",))
        self.tree.setColumnWidth(0, 10)

        # Create layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)

        # Populate PluginForm
        try:
            self.PopulateTree(self.ea)
        except Exception, e:
            print '[*] Exception occurred during tree population: %s' % str(e)
            self.Close(0)
            raise

        # Connect signal
        self.tree.itemActivated.connect(self.ItemActivatedSlot)

    def OnClose(self, form):
        """
        Called when the plugin form is closed.
        Delete singleton
        """
        print '[*] OnClose for 0x%06X' % self.ea
        oregamiPluginDestructor(self.ea, self.tabMode)

    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        tabName = 'Oregami'

        if self.tabMode:
            return PluginForm.Show(self, tabName)
        else:
            return _ida_kernwin.plgform_show(self.__clink__, self, tabName, PluginForm.FORM_CENTERED | PluginForm.FORM_PERSIST)
