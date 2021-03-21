# coding=utf-8
import idaapi
from Qing.action_utils import Action
from PyQt5 import QtWidgets
import idc


class TestAction(Action):
    description = "Test"
    hotkey = ''

    def __init__(self):
        super(TestAction, self).__init__()

    def activate(self, ctx):
        print("testAction activate")
        return 1

    def update(self, ctx):
        print("testAction update")
        return idaapi.AST_ENABLE_ALWAYS


class MenuAttach(idaapi.plugin_t):
    wanted_name = "menu attach"
    wanted_hotkey = ''
    # flags = idaapi.PLUGIN_MOD
    flags = 0
    comment = ''
    help = ''

    menu_name = 'View/Graphs/'

    def __init__(self):
        super(MenuAttach, self).__init__()
        self.testAction = TestAction()

    def init(self):
        testAction = self.testAction
        action_desc = idaapi.action_desc_t(testAction.name, testAction.description, testAction, testAction.hotkey,
                                           'TestActio tip', 199)
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(MenuAttach.menu_name, testAction.name, idaapi.SETMENU_APP)
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.detach_action_from_menu(MenuAttach.menu_name, self.testAction.name)

    def run(self, arg):

        text, confirmed = QtWidgets.QInputDialog.getText(
            None,
            "Input Dialog",
            "Please enter an hexadecimal address:",
            text="%X" % 123,
        )
        if confirmed:
            print(text)
        # z = idc.AskStr("hello", "地址或函数名")
        # print(z)


def PLUGIN_ENTRY():
    return MenuAttach()
