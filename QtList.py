# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets
import idaapi

from PyQt5.QtWidgets import QVBoxLayout, QListView, QGroupBox, QHBoxLayout, QCheckBox
from PyQt5.QtCore import QStringListModel

from ida_kernwin import _ida_kernwin
from idaapi import PluginForm


# import sys
# defaultencoding = 'utf-8'
# if sys.getdefaultencoding() != defaultencoding:
#     reload(sys)
#     sys.setdefaultencoding(defaultencoding)

class StructureBuilder(idaapi.PluginForm):
    def __init__(self):
        super(StructureBuilder, self).__init__()
        # self.structure_model = structure_model
        self.parent = None
        self.qList = ['Item 1', 'Item 2', 'Item 3', 'Item 4']
        self.slm = None
        self.listview = None
        self.taginput = QtWidgets.QLineEdit()
        self.funcinput = QtWidgets.QLineEdit()

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        # self.parent.resize(400, 600)
        self.parent.setWindowTitle('Function Control')
        layout = QtWidgets.QHBoxLayout()

        tagout = QtWidgets.QVBoxLayout()
        listView = QListView()
        self.listview = listView
        slm = QStringListModel()
        self.slm = slm
        slm.setStringList(self.qList)
        listView.setModel(slm)
        listView.clicked.connect(self.clicked)
        tagout.addWidget(listView)

        grid = QtWidgets.QGridLayout()
        grid.addWidget(self.taginput, 0, 0)
        modifybtn = QtWidgets.QPushButton("&modify")
        grid.addWidget(modifybtn, 0, 1)
        delbtn = QtWidgets.QPushButton("&del")
        grid.addWidget(delbtn, 0, 2)
        addbtn = QtWidgets.QPushButton("&add")
        grid.addWidget(addbtn, 0, 3)
        tagout.addLayout(grid)
        layout.addLayout(tagout)

        funlayout = QtWidgets.QVBoxLayout()
        listWidget = QtWidgets.QListWidget()
        listWidget.addItem("Item - 1")
        listWidget.addItem("Item - 2")
        listWidget.addItem("Item - 3")
        listWidget.addItem("Item - 4")
        listWidget.itemClicked.connect(self.clicked2)
        funlayout.addWidget(listWidget)

        grid = QtWidgets.QGridLayout()
        grid.addWidget(self.funcinput, 0, 0)
        addbtn = QtWidgets.QPushButton("&add")
        addbtn.clicked.connect(self.testbtn)
        grid.addWidget(addbtn, 0, 1)
        delbtn = QtWidgets.QPushButton("&del")
        grid.addWidget(delbtn, 0, 2)
        funlayout.addLayout(grid)
        layout.addLayout(funlayout)

        groupBox = QGroupBox("Checkboxes")
        groupBox.setFlat(False)

        checklayout = QHBoxLayout()
        self.checkBox1 = QCheckBox("&Checkbox1")
        self.checkBox1.setChecked(True)
        self.checkBox1.stateChanged.connect(lambda: self.btnstate(self.checkBox1))
        checklayout.addWidget(self.checkBox1)

        self.checkBox2 = QCheckBox("Checkbox2")
        self.checkBox2.toggled.connect(lambda: self.btnstate(self.checkBox2))
        checklayout.addWidget(self.checkBox2)

        self.checkBox3 = QCheckBox("tristateBox")
        self.checkBox3.setTristate(True)
        self.checkBox3.setCheckState(QtCore.Qt.PartiallyChecked)
        self.checkBox3.stateChanged.connect(lambda: self.btnstate(self.checkBox3))
        checklayout.addWidget(self.checkBox3)
        groupBox.setLayout(checklayout)
        # listWidget.setWindowTitle('QListwidget 例子')

        # layout.addWidget(listWidget)
        layout.addWidget(groupBox)
        self.parent.setLayout(layout)

    def testbtn(self):
        print("testbtn")

    def OnClose(self, form):
        pass

    def clicked(self, model_index):
        print("你选择了: " + self.qList[model_index.row()])

    def clicked2(self, item):
        print("choose:" + item.text())

    def btnstate(self, btn):
        chk1Status = self.checkBox1.text() + ", isChecked=" + str(self.checkBox1.isChecked()) + ', chekState=' + str(
            self.checkBox1.checkState()) + "\n"
        chk2Status = self.checkBox2.text() + ", isChecked=" + str(self.checkBox2.isChecked()) + ', checkState=' + str(
            self.checkBox2.checkState()) + "\n"
        chk3Status = self.checkBox3.text() + ", isChecked=" + str(self.checkBox3.isChecked()) + ', checkState=' + str(
            self.checkBox3.checkState()) + "\n"
        print(chk1Status + chk2Status + chk3Status)

    def Show(self, caption=None, options=0):
        # return idaapi.PluginForm.Show(self, "QING")
        # return idaapi.PluginForm.Show(self, caption, options=options)
        return _ida_kernwin.plgform_show(self.__clink__, self, "QING",
                                         PluginForm.FORM_CENTERED | PluginForm.FORM_PERSIST)
