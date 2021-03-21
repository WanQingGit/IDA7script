from Qing.common import *


class MyChooser(idaapi.Choose):

    def __init__(self, title, columns, items, embedded=True):
        idaapi.Choose.__init__(self, title, columns, embedded=embedded)
        self.items = items

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items
        self.Refresh()

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        to = self.items[n][3]
        idc.Jump(int(to, 16))


PLUGIN_CHOOSER_FORM_TEMPLATE = \
r"""BUTTON YES* OK
BUTTON CANCEL Cancel
%s
<call relation:{Chooser}>
"""

from idaapi import Form


class MyChooserForm(Form):

    def __init__(self, title, chooser):
        self.chooser = chooser
        template = PLUGIN_CHOOSER_FORM_TEMPLATE % title
        Form.__init__(self, template, {"Chooser": Form.EmbeddedChooserControl(chooser)})


CHOOSER_COLUMN_NAMES = ["Function", "Type", "FuncOff", "Address", "Time", "Text"]
CHOOSER_COLUMN_SIZES = [9, 5, 9, 8, 3, 35]
CHOOSER_COLUMNS = [list(c) for c in  # [['Direction', 6], ['Type', 7], ['Address', 6], ['Text', 40]]
                   zip(CHOOSER_COLUMN_NAMES, CHOOSER_COLUMN_SIZES)]


def choosershow(rows):
    chooser = MyChooser("call or called info", CHOOSER_COLUMNS, rows)
    form = MyChooserForm("function call info", chooser)
    form.Compile()
    form.Execute()
    form.Free()
