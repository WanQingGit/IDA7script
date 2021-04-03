# coding=utf-8
import idc
from Qing import common
import re
from Qing.QtBase import *
from PyQt5 import QtCore, QtGui, QtWidgets

_var_debug = common.Debugger()

_var_debug.off()


class VarAnalyzer(QtUiShow):

    def __init__(self, dbginfo):
        super(VarAnalyzer, self).__init__()
        self.dbginfo = dbginfo
        self.funcargs = dbginfo.funcarg
        self.watchfn = {}
        self.funclist = {}
        # self.parent = None
        self.argtree = None
        self.watchtree = None
        self.funcinput = None
        self.addrinput = None
        self.printout = None
        self.id = VarAnalyzer.ninstance
        VarAnalyzer.ninstance = self.id + 1


    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('ArgAnalyzer-' + str(self.id))

        btn_Clone = QtWidgets.QPushButton("&Clone")
        btn_Clone.clicked.connect(self.clone)
        btn_watch = QtWidgets.QPushButton("&WatchPtr")
        btn_watch.clicked.connect(self.add_var_watch)
        btn_screenEA = QtWidgets.QPushButton("&ScreenEA")
        btn_screenEA.clicked.connect(lambda: self.printout.setText("0x%X" % idc.ScreenEA()))
        btn_origin = QtWidgets.QPushButton("&Backup")
        btn_resolve = QtWidgets.QPushButton("Restore")
        text_out = QtWidgets.QLineEdit()
        self.printout = text_out
        btn_recognize = QtWidgets.QPushButton("Recognize Shape")
        btn_recognize.setStyleSheet("QPushButton {width: 100px; height: 20px;}")

        # btn_finalize.setShortcut("f")

        # struct_view = QtWidgets.QTableView()
        # struct_view.setModel(self.structure_model)
        # # struct_view.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        #
        # struct_view.verticalHeader().setVisible(False)
        # struct_view.verticalHeader().setDefaultSectionSize(24)
        # struct_view.horizontalHeader().setStretchLastSection(True)
        # struct_view.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_Clone, 0, 0)
        grid_box.addWidget(btn_screenEA, 0, 1)
        grid_box.addWidget(btn_watch, 0, 2)
        grid_box.addWidget(btn_origin, 0, 3)
        grid_box.addWidget(btn_resolve, 0, 4)

        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, 5)

        grid_box.addWidget(text_out, 0, 6)
        grid_box.addWidget(btn_recognize, 0, 7)

        vertical_box = QtWidgets.QVBoxLayout()
        horizontal_box = QtWidgets.QHBoxLayout()

        argLayout = QtWidgets.QVBoxLayout()
        treeselectmode = QtWidgets.QAbstractItemView.ExtendedSelection
        argtree = QtWidgets.QTreeWidget()
        self.argtree = argtree
        # 设置列数
        argtree.setColumnCount(2)
        # 设置树形控件头部的标题
        argtree.setHeaderLabels(['argument', 'Value'])
        argLayout.addWidget(argtree)
        # 设置根节点
        # funcname=idc.get_func_off_str(funcarg.addr)
        # root.setText(0, funcname)
        # root.setIcon(0, QtWidgets.QIcon('./images/root.png'))

        # 设置树形控件的列的宽度
        argtree.setColumnWidth(0, 150)

        # TODO 优化3 给节点添加响应事件
        argtree.clicked.connect(self.onClicked)
        argtree.doubleClicked.connect(self.onDClicked)
        argtree.setSelectionMode(treeselectmode)
        # 节点全部展开
        # argtree.expandAll()

        fneditlayout = QtWidgets.QHBoxLayout()
        argLayout.addLayout(fneditlayout)

        lineedit = QtWidgets.QLineEdit()
        lineedit.setPlaceholderText("funcname")
        self.funcinput = lineedit
        fneditlayout.addWidget(lineedit)

        btnadd = QtWidgets.QPushButton("add")
        btnadd.clicked.connect(self.add_func)
        fneditlayout.addWidget(btnadd)

        spacer = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding)
        fneditlayout.addSpacerItem(spacer)
        btndel = QtWidgets.QPushButton("&del")
        btndel.clicked.connect(self.del_func)
        fneditlayout.addWidget(btndel)

        updatewatch = QtWidgets.QPushButton("&update")
        updatewatch.clicked.connect(self.load_data)
        fneditlayout.addWidget(updatewatch)

        btnwatch = QtWidgets.QPushButton("&[un]watch")
        btnwatch.clicked.connect(self.add_func_watch)
        fneditlayout.addWidget(btnwatch)

        watchLayout = QtWidgets.QVBoxLayout()

        watchtree = QtWidgets.QTreeWidget()
        self.watchtree = watchtree
        # treeView.setGeometry(QtCore.QRect(400, 150, 256, 192))
        # treeView.setObjectName("treeView")
        watchtree.setColumnCount(2)
        watchtree.setHeaderLabels(['Pointer', 'Value'])
        watchtree.clicked.connect(self.onClicked2)
        watchtree.doubleClicked.connect(self.onDClicked)
        watchLayout.addWidget(watchtree)

        watcheditlayout = QtWidgets.QHBoxLayout()
        watchLayout.addLayout(watcheditlayout)

        addrinput = QtWidgets.QLineEdit()
        self.addrinput = addrinput
        addrinput.setPlaceholderText("addr type np name")
        watcheditlayout.addWidget(addrinput)
        btnwatch = QtWidgets.QPushButton("&watch")
        btnwatch.clicked.connect(self.watch_var)
        watcheditlayout.addWidget(btnwatch)

        spacer = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding)
        watcheditlayout.addSpacerItem(spacer)
        btndel = QtWidgets.QPushButton("&del")
        # btndel.clicked.connect(self.addOrDelFunc)
        watcheditlayout.addWidget(btndel)
        # combo2 = QtWidgets.QComboBox(self.parent)
        # combo2.addItem("argument pointer")
        # combo2.addItem("argument variable")
        # combo2.activated[str].connect(self.onActivated)

        horizontal_box.addLayout(argLayout)
        horizontal_box.addLayout(watchLayout)
        horizontal_box.setStretchFactor(argLayout, 2)
        horizontal_box.setStretchFactor(watchLayout, 3)

        vertical_box.addLayout(horizontal_box)
        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

    def watch_var(self):
        pass
        # text = self.addrinput.text().encode('utf-8').strip()
        # vals = re.sub("\s+", "_", text).split("_")
        # if len(vals) != 4:
        #     return
        # ea = vals[0]
        # t = vals[1]
        # np = vals[2]
        # name = vals[3]
        # v = self.dbginfo.read_value(t, ea, np)
        # self.watchtree_append()

    def add_func(self):
        _var_debug()
        funcname = self.funcinput.text().encode('utf-8').strip()
        if funcname:
            afn = idc.LocByName(funcname)
            if afn & 1:
                self.funcinput.setText(funcname + " is not a function")
                return False
        else:
            ea = idc.ScreenEA()
            func = idaapi.get_func(ea)
            if not func:
                return False
            afn = func.startEA
        dbginfo = self.dbginfo
        arg = dbginfo.append_func_watch(afn)
        if not idc.AddBpt(afn):
            idc.EnableBpt(afn, True)
        # dbginfo.addbp("RET", afn)
        if arg:
            self.argtree_append(arg)
            return True
        return False

    def add_var_watch(self):
        argtree = self.argtree
        item = argtree.currentItem()
        parent = item.parent()
        if not parent:
            return
        addrtext = item.text(1).strip()
        if re.search("^0x[\da-fA-F]{5,15}$", addrtext):
            ea = int(addrtext[2:], 16)
        else:
            return
        if hasattr(parent, "func"):
            name = item.text(0)
        else:
            name = parent.text(0)
            parent = parent.parent()
        funcarg = parent.func
        arginfos = funcarg.arginfos
        info = arginfos[name]
        var = self.dbginfo.add_watch_var(common.WordObj(ea), name, info.type, info.np)

    def add_func_watch(self):
        items = self.argtree.selectedItems()
        _var_debug()
        for item in items:
            parent = item.parent()
            if parent:
                if parent.parent():
                    continue
                varname = item.text(0)
                funcarg = parent.func
                if varname in funcarg.watchvar:
                    item.setBackground(0, VarAnalyzer.brush_white)
                    funcarg.watchvar.remove(varname)
                else:
                    funcarg.watchvar.add(varname)
                    item.setBackground(0, VarAnalyzer.brush_green)
            else:
                funcarg = item.func
                if not funcarg.watchptr:
                    funcarg.watchptr = True
                    funcarg[self.id]["argnode"].setBackground(0, VarAnalyzer.brush_green)

                else:
                    funcarg.watchptr = False
                    funcarg[self.id]["argnode"].setBackground(0, VarAnalyzer.brush_white)
                self.watchnode_state_update(funcarg)

        # self.watchtree_append(funcarg)

    def del_func(self):
        argtree = self.argtree
        item = argtree.currentItem()
        parent = item.parent()
        if parent:
            parent.remove(item)
            return

        root = argtree.invisibleRootItem()
        funcarg = item.func
        self.dbginfo.del_func_watch(funcarg.addr)
        root.removeChild(item)
        usrdata = funcarg[self.id]
        if "watchnode" in usrdata:
            node = usrdata["watchnode"]
            node.setBackground(0, VarAnalyzer.brush_red)

    def argnode_update(self, funcarg):
        argtree = self.argtree

        root = argtree.invisibleRootItem()
        try:
            node = funcarg[self.id]["argnode"]
            root.removeChild(node)
        except:
            pass
        self.argtree_append(funcarg)

    def watchnode_state_update(self, funcarg):
        usrdata = funcarg[self.id]
        if "watchnode" in usrdata:
            node = usrdata["watchnode"]
            if funcarg.watchptr:
                node.setBackground(0, VarAnalyzer.brush_white)
            else:
                node.setBackground(0, VarAnalyzer.brush_white)
        else:
            self.watchtree_append(funcarg)

    def watchnode_update(self, funcarg):
        argtree = self.argtree
        root = argtree.invisibleRootItem()
        try:
            node = funcarg[self.id]["watchnode"]
            root.removeChild(node)
        except:
            pass
        self.watchtree_append(funcarg)

    def argtree_append(self, funcarg):
        argtree = self.argtree
        funcname = idc.get_func_off_str(funcarg.addr)
        # self.addFuncNode(funcname, funcarg)
        root = QtWidgets.QTreeWidgetItem(argtree)
        root.setText(0, funcname)
        if funcarg.watchptr:
            root.setBackground(0, VarAnalyzer.brush_green)
        root.setText(1, str(funcarg.narg))
        root.func = funcarg
        funcarg[self.id]['argnode'] = root
        watchvar = funcarg.watchvar
        if len(funcarg.arguments) > 0:
            for k, v in funcarg.arguments.items():
                propnode = QtWidgets.QTreeWidgetItem(root)
                propnode.setText(0, k)
                if k in watchvar:
                    propnode.setBackground(0, VarAnalyzer.brush_green)
                lenv = len(v)
                lensetv = len(set(v))
                propnode.setText(1, str(lensetv))
                if lensetv == 1:
                    child = QtWidgets.QTreeWidgetItem(propnode)
                    child.setText(0, "[:" + str(lenv) + "]")
                    child.setText(1, str(v[0]))
                else:
                    prevValue = None
                    for i in range(lenv):
                        value = v[i]
                        if value != prevValue:
                            child = QtWidgets.QTreeWidgetItem(propnode)
                            child.setText(0, str(i))
                            child.setText(1, str(value))
                            prevValue = value
        else:
            arginfos = funcarg.arginfos
            for name, _ in arginfos.items():
                propnode = QtWidgets.QTreeWidgetItem(root)
                propnode.setText(0, name)
                if name in watchvar:
                    propnode.setBackground(0, VarAnalyzer.brush_green)

        if funcarg.watchptr:
            if "watchnode" in funcarg[self.id]:
                self.watchnode_update(funcarg)
            else:
                self.watchtree_append(funcarg)

    def watchtree_append(self, funcarg):
        watchtree = self.watchtree
        root = QtWidgets.QTreeWidgetItem(watchtree)
        funcname = idc.get_func_off_str(funcarg.addr)
        root.setText(0, funcname)
        root.setText(1, str(funcarg.nwatch))
        root.func = funcarg
        funcarg[self.id]["watchnode"] = root
        if not funcarg.watchptr:
            root.setBackground(0, VarAnalyzer.brush_red)
        else:
            root.setBackground(0, VarAnalyzer.brush_white)
        for k, v in funcarg.pointer.items():
            propnode = QtWidgets.QTreeWidgetItem(root)
            lenv = len(v)
            propnode.setText(0, k)
            propnode.setText(1, str(lenv))
            QtUiShow.appendchild(propnode, v, True)
            # for i, dt in v.items():
            #     child = QtWidgets.QTreeWidgetItem(propnode)
            #     child.setText(0, str(i))
            #     # dt = v[i]
            #     child.setText(1, str(dt[0]))
            #     for d in dt[1:]:
            #         # child=QtWidgets.QTreeWidgetItem(child)
            #         if isinstance(d, NumObj):
            #             child = QtWidgets.QTreeWidgetItem(child)
            #             child.setText(0, str(d))
            #         else:
            #             QtUiShow.appendchild(child, d)

    def load_data(self):
        argtree = self.argtree
        watchtree = self.watchtree
        watchtree.clear()
        argtree.clear()
        watchfunc = self.dbginfo.watchfunc
        for _, funcarg in watchfunc.items():
            self.argtree_append(funcarg)

    def onActivated(self, text):
        # self.lbl.setText(text)
        print(text)

    def OnClose(self, form):
        print("window {} closed".format(self.id))

    def onClicked(self, qmodelindex):
        item = self.argtree.currentItem()
        self.out(item)

    def onClicked2(self, qmodelindex):
        self.out(self.watchtree.currentItem())

    def out(self, item):
        text = 'Key=%s,value=%s' % (item.text(0), item.text(1))
        print(text)
        self.printout.setText(text)

    def onDClicked(self, qmodelindex):  # QModelIndex
        try:
            item = self.argtree.currentItem()
            if not item:
                return
            parent = item.parent()
            if parent:
                addtext = item.text(1).strip()
                if re.search("^0x[\da-fA-F]{5,15}$", addtext):
                    idc.Jump(int(addtext[2:], 16))
            else:
                idc.Jump(item.func.addr)
            print('DClick Key=%s,value=%s' % (item.text(0), item.text(1)))
        except:
            import traceback
            traceback.print_exc()

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)

    def clone(self):
        new_win = VarAnalyzer(self.dbginfo)
        new_win.Show()
        new_win.load_data()
