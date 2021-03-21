from PyQt5 import QtWidgets, QtGui, QtCore
import idaapi
from Qing.common import NumObj


class QtUiShow(idaapi.PluginForm):
    ninstance = 0
    brush_red = QtGui.QBrush(QtCore.Qt.red)
    brush_white = QtGui.QBrush(QtCore.Qt.white)
    brush_green = QtGui.QBrush(QtCore.Qt.green)
    brush_dark = QtGui.QBrush(QtCore.Qt.darkGray)

    def __init__(self):
        super(QtUiShow, self).__init__()
        self.parent = None

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        raise NotImplemented

    @staticmethod
    def appendchild(parent, val, ign_same=False):
        preval = None
        if isinstance(val, dict):
            for k, v in val.iteritems():
                child = QtWidgets.QTreeWidgetItem(parent)
                child.setText(0, str(k))
                if ign_same:
                    if v == preval:
                        continue
                    else:
                        preval = v
                if isinstance(v, NumObj):
                    child.setText(1, str(v))
                else:
                    QtUiShow.appendchild(child, v)

                # else:
                #     islist = isinstance(v, list)
                #     lenv = len(v)
                #     if islist and lenv >= 1 and isinstance(v[0], NumObj):
                #         if lenv == 1:
                #             child.setText(1, str(v[0]))
                #         elif lenv > 1 and v[-1] == int:
                #             child.setText(1, str(v[0]))
                #             for i in range(1, lenv - 2):
                #                 child = QtWidgets.QTreeWidgetItem(child)
                #                 child.setText(0, "ptr")
                #                 child.setText(1, str(v[i]))
                #             QtUiShow.appendchild(child, v[-2])
                #         else:
                #             QtUiShow.appendchild(child, v)
                #     else:
                #         QtUiShow.appendchild(child, v)
            return parent
        elif isinstance(val, list):
            if val[-1] == int:
                lenv = len(val)
                for k in range(0, lenv - 2):
                    parent = QtWidgets.QTreeWidgetItem(parent)
                    parent.setText(0, "ptr")
                    parent.setText(1, str(val[k]))
                QtUiShow.appendchild(parent, val[-2])
            else:
                for i, v in enumerate(val):
                    child = QtWidgets.QTreeWidgetItem(parent)
                    # if isinstance(v,NumObj):
                    #     child = QtWidgets.QTreeWidgetItem(parent)
                    #     child.setText(1, str(val))
                    # else:
                    #     pass
                    child.setText(0, str(i))
                    if isinstance(v, NumObj):
                        child.setText(1, str(v))
                    else:
                        QtUiShow.appendchild(child, v)

                    # if child != parent:
                    #     child.setText(0, str(i))
            return parent
        else:
            child = QtWidgets.QTreeWidgetItem(parent)
            child.setText(1, str(val))
            return child
