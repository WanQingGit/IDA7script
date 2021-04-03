# coding=utf-8
from PyQt5 import QtCore, QtGui, QtWidgets
import idaapi, idc
from Qing.common import NumObj, WordObj
from Qing import config, common
import re
from Qing import callviewer, QtBase

_reg_debug = common.Debugger()
_reg_debug.suspend = False


class FuncTracer(QtBase.QtUiShow):
    def __init__(self, dbginfo):
        super(FuncTracer, self).__init__()
        self.dbginfo = dbginfo
        self.funcargs = dbginfo.funcarg
        self.watchfn = {}
        self.funclist = {}
        self.parent = None
        self.bptree = None
        self.watchtree = None
        self.bpinput = None
        self.addrinput = None
        self.printout = None
        self.check_trace = None
        self.check_enable = None
        self.id = FuncTracer.ninstance
        FuncTracer.ninstance = self.id + 1

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.setWindowTitle('CallTracer-' + str(self.id))

        btn_Clone = QtWidgets.QPushButton("&Clone")
        btn_Clone.clicked.connect(self.clone)
        btn_update = QtWidgets.QPushButton("&Update")
        btn_update.clicked.connect(self.load_data)
        btn_backup = QtWidgets.QPushButton("&Backup")
        btn_backup.clicked.connect(self.bp_back)
        btn_restore = QtWidgets.QPushButton("&Restore")
        btn_restore.clicked.connect(self.bp_restore)
        btn_monitor = QtWidgets.QPushButton("Call Graph")
        btn_monitor.clicked.connect(self.showcall)

        btn_save = QtWidgets.QPushButton("&Save")
        btn_save.clicked.connect(self.callinfo_save)
        btn_load = QtWidgets.QPushButton("&Load")
        btn_load.clicked.connect(self.callinfo_load)
        btn_clear = QtWidgets.QPushButton("&Clear")
        btn_clear.clicked.connect(self.callinfo_claer)
        check_trace = QtWidgets.QCheckBox("TraceMode")
        check_trace.setTristate(True)
        check_trace.stateChanged.connect(self.mode_switch)
        self.check_trace = check_trace
        text_out = QtWidgets.QLineEdit()
        self.printout = text_out

        check_enable = QtWidgets.QCheckBox("EnableBp")
        check_enable.stateChanged.connect(self.enable_bps)
        self.check_enable = check_enable

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_Clone, 0, 0)
        grid_box.addWidget(btn_update, 0, 1)
        grid_box.addWidget(btn_backup, 0, 2)
        grid_box.addWidget(btn_restore, 0, 3)
        grid_box.addWidget(btn_monitor, 0, 4)

        grid_box.addWidget(btn_save, 0, 5)
        grid_box.addWidget(btn_load, 0, 6)
        grid_box.addWidget(btn_clear, 0, 7)
        grid_box.addWidget(check_trace, 0, 8)
        grid_box.addWidget(check_enable, 0, 9)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, 10)

        grid_box.addWidget(text_out, 0, 11)
        vertical_box = QtWidgets.QVBoxLayout()
        horizontal_box = QtWidgets.QHBoxLayout()

        argLayout = QtWidgets.QVBoxLayout()
        treeselectmode = QtWidgets.QAbstractItemView.ExtendedSelection
        bptree = QtWidgets.QTreeWidget()
        self.bptree = bptree
        # 设置列数
        bptree.setColumnCount(2)
        # 设置树形控件头部的标题
        bptree.setHeaderLabels(['Name', 'Value'])
        argLayout.addWidget(bptree)
        # 设置根节点
        # funcname=idc.get_func_off_str(funcarg.addr)
        # root.setText(0, funcname)
        # root.setIcon(0, QtWidgets.QIcon('./images/root.png'))

        # 设置树形控件的列的宽度
        bptree.setColumnWidth(0, 150)

        # TODO 优化3 给节点添加响应事件
        bptree.clicked.connect(self.onClicked)
        bptree.doubleClicked.connect(self.onDClicked)
        bptree.setSelectionMode(treeselectmode)
        # 节点全部展开
        # bptree.expandAll()

        fneditlayout = QtWidgets.QHBoxLayout()
        argLayout.addLayout(fneditlayout)

        lineedit = QtWidgets.QLineEdit()
        lineedit.setPlaceholderText("default screenEA")
        self.bpinput = lineedit
        fneditlayout.addWidget(lineedit)

        btnadd = QtWidgets.QPushButton("add")
        btnadd.clicked.connect(self.add_bp)
        fneditlayout.addWidget(btnadd)

        spacer = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding)
        fneditlayout.addSpacerItem(spacer)
        btndel = QtWidgets.QPushButton("&del")
        btndel.clicked.connect(self.del_func)
        fneditlayout.addWidget(btndel)

        breakbtn = QtWidgets.QPushButton("&[un]break")
        breakbtn.clicked.connect(self.load_data)
        fneditlayout.addWidget(breakbtn)

        btnwatch = QtWidgets.QPushButton("&[un]watch")
        btnwatch.clicked.connect(self.add_bp_watch)
        fneditlayout.addWidget(btnwatch)

        btnaddright = QtWidgets.QPushButton("Test Js Hook")
        btnaddright.clicked.connect(self.add_from_watchvar)
        fneditlayout.addWidget(btnaddright)

        watchLayout = QtWidgets.QVBoxLayout()

        watchtree = QtWidgets.QTreeWidget()
        self.watchtree = watchtree
        # treeView.setGeometry(QtCore.QRect(400, 150, 256, 192))
        # treeView.setObjectName("treeView")
        watchtree.setColumnCount(2)
        watchtree.setHeaderLabels(['Pointer', 'Value'])
        watchtree.clicked.connect(self.onClicked2)
        watchtree.setSelectionMode(treeselectmode)
        watchLayout.addWidget(watchtree)

        watcheditlayout = QtWidgets.QHBoxLayout()
        watchLayout.addLayout(watcheditlayout)

        addrinput = QtWidgets.QLineEdit()
        self.addrinput = addrinput
        addrinput.setPlaceholderText("reg type np name")
        watcheditlayout.addWidget(addrinput)
        btnwatch = QtWidgets.QPushButton("&watch")
        btnwatch.clicked.connect(self.add_var)
        watcheditlayout.addWidget(btnwatch)

        spacer = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding)
        watcheditlayout.addSpacerItem(spacer)
        takebtn = QtWidgets.QPushButton("&take")
        takebtn.clicked.connect(self.read_var)
        watcheditlayout.addWidget(takebtn)
        btndel = QtWidgets.QPushButton("&unattach")
        btndel.clicked.connect(self.unattach)
        watcheditlayout.addWidget(btndel)

        btn_attach = QtWidgets.QPushButton("&attach bp selected")
        btn_attach.clicked.connect(self.attach_bp_selected)
        watcheditlayout.addWidget(btn_attach)

        horizontal_box.addLayout(argLayout)
        horizontal_box.addLayout(watchLayout)

        vertical_box.addLayout(horizontal_box)

        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

    def add_var(self):
        text = self.addrinput.text().encode('utf-8').strip()
        vals = re.sub("\s+", " ", text).split(" ")
        if len(vals) != 4:
            return
        ea = int(vals[0], 16)
        t = vals[1]
        np = int(vals[2])
        name = vals[3]
        ea = WordObj(ea)
        if ea.ref is None:
            return
        var = self.dbginfo.add_watch_var(ea, name, t, np)
        if var is not None:
            # v=self.dbginfo.read_value(t,ea,np)
            self.watchtree_append(var)

    def read_var(self):
        item = self.watchtree.currentItem()
        if item.parent():
            return
        var = item.var
        if self.dbginfo.read_var(var):
            self.watchnode_update(var)

    def add_bp(self):
        _reg_debug()
        text = self.bpinput.text().encode('utf-8').strip()
        if len(text) > 5:
            ea = int(text, 16)
        else:
            ea = idc.ScreenEA()
        dbginfo = self.dbginfo

        res = dbginfo.addTracebp(ea)
        dbginfo.addcallinfo()
        if res:
            self.bpnode_update(res)
            return True
        return False

    def add_bp_watch(self):
        pass
        # item = self.bptree.currentItem()
        # parent = item.parent()
        # if parent:
        #     if parent.parent():
        #         return False
        #     varname = item.text(0)
        #     watchvar = parent.var
        #     if varname in funcarg.watchvar:
        #         item.setBackground(0, FuncTracer.brush_white)
        #         funcarg.watchvar.remove(varname)
        #     else:
        #         funcarg.watchvar.add(varname)
        #         item.setBackground(0, FuncTracer.brush_green)
        #     return
        # funcarg = item.func
        # if not funcarg.watchptr:
        #     funcarg.watchptr = True
        #     funcarg[self.id]["bpnode"].setBackground(0, FuncTracer.brush_green)
        # else:
        #     funcarg.watchptr = False
        #     funcarg[self.id]["bpnode"].setBackground(0, FuncTracer.brush_white)
        # self.watchnode_state_update(funcarg)

        # self.watchtree_append(funcarg)

    def del_func(self):
        bptree = self.bptree
        item = bptree.currentItem()
        parent = item.parent()
        if parent:
            parent.remove(item)
            return
        root = bptree.invisibleRootItem()
        funcarg = item.func
        self.dbginfo.del_func_watch(funcarg.addr)
        root.removeChild(item)
        usrdata = funcarg[self.id]
        if "watchnode" in usrdata:
            node = usrdata["watchnode"]
            node.setBackground(0, FuncTracer.brush_red)

    def add_from_watchvar(self):
        _reg_debug()
        from QFrida import FuncHook
        import idautils
        FuncHook.fnHook(idautils.Functions())

    def bpnode_update(self, funcbp):
        bptree = self.bptree
        root = bptree.invisibleRootItem()
        try:
            node = funcbp[self.id]["bpnode"]
            root.removeChild(node)
        except:
            pass
        root = self.bptree_append(funcbp)
        root.setExpanded(True)

    def watchnode_state_update(self, funcarg):
        usrdata = funcarg[self.id]
        if "watchnode" in usrdata:
            node = usrdata["watchnode"]
            if funcarg.watchptr:
                node.setBackground(0, FuncTracer.brush_white)
            else:
                node.setBackground(0, FuncTracer.brush_white)
        else:
            self.watchtree_append(funcarg)

    def watchnode_update(self, var):
        watchtree = self.watchtree
        root = watchtree.invisibleRootItem()
        try:
            node = var[self.id]["watchnode"]
            root.removeChild(node)
        except:
            pass
        self.watchtree_append(var)

    def bptree_append(self, funcbps):
        bptree = self.bptree
        # self.addFuncNode(funcname, funcarg)
        root = QtWidgets.QTreeWidgetItem(bptree)
        root.setText(0, funcbps.name)
        root.setText(1, str(len(funcbps.bps)))
        root.bps = funcbps
        funcbps[self.id]['bpnode'] = root
        for offset, varlist in funcbps.bps.items():
            node = QtWidgets.QTreeWidgetItem(root)
            node.setText(0, "+%X" % offset)
            node.offset = offset
            lenv = len(varlist)
            node.setText(1, str(lenv))
            for reg, varinfo in varlist.items():
                varroot = QtWidgets.QTreeWidgetItem(node)
                var = varinfo['var']
                values = varinfo['values']
                varroot.setText(0, " ".join([reg, var.t]))
                lenv = len(values)
                varroot.setText(1, lenv)
                prevValue = None
                for i in range(lenv):
                    child = QtWidgets.QTreeWidgetItem(varroot)
                    child.setText(0, str(i))
                    d = values[i]
                    if prevValue:
                        if d != prevValue:
                            child.setBackground(1, FuncTracer.brush_red)
                    prevValue = d
                    lend = len(d)
                    for k in range(0, lend - 1):
                        child = QtWidgets.QTreeWidgetItem(child)
                        child.setText(0, "ptr")
                        child.setText(1, str(d[k]))
                    FuncTracer.appendchild(child, d[-1])
        return root

    def watchtree_append(self, watchvar):
        watchtree = self.watchtree
        root = QtWidgets.QTreeWidgetItem(watchtree)
        varname = watchvar.name
        root.setText(0, varname)
        root.setText(1, watchvar.ea.s)
        root.var = watchvar
        watchvar[self.id]["watchnode"] = root
        values = watchvar.values
        positons = watchvar.positions
        lenv = len(values)
        prevValue = None
        for i in range(lenv):
            child = QtWidgets.QTreeWidgetItem(root)
            child.setText(0, str(i))
            child.setText(1, positons[i])
            d = values[i]
            if prevValue:
                if prevValue != d:
                    child.setBackground(1, FuncTracer.brush_red)
            prevValue = d

            lend = len(d)
            for k in range(0, lend - 1):
                child = QtWidgets.QTreeWidgetItem(child)
                child.setText(0, "ptr")
                child.setText(1, str(d[k]))
            FuncTracer.appendchild(child, d[-1])

    def unattach(self):
        _reg_debug()
        watchtree = self.watchtree
        watchItems = watchtree.selectedItems()
        dbginfo = self.dbginfo
        for watchItem in watchItems:
            parent = watchItem.parent()
            if parent:
                if not hasattr(parent, "var"):
                    continue
                var = parent.var
                s = watchItem.text(1).split("+")
                ea = idc.LocByName(str(s[0]))
                if not ea:
                    continue
                if len(s) > 1:
                    offset = int(s[1], 16)
                else:
                    offset = 0
                dbginfo.delbp2(ea, offset, var.ea.v)
            else:
                continue

    def attach_bp_selected(self):
        _reg_debug()
        watchtree = self.watchtree
        watchItem = watchtree.currentItem()
        if watchItem.parent():
            return
        watchvar = watchItem.var
        bptree = self.bptree
        bpitems = bptree.selectedItems()
        fbplist = set()
        for bpItem in bpitems:
            bpparent = bpItem.parent()
            if bpparent:
                if not hasattr(bpItem, "offset"):
                    continue
                funcbps = bpparent.bps
                if funcbps.addvar(watchvar, bpItem.offset):
                    fbplist.add(funcbps)
            else:
                funcbps = bpItem.bps
                if funcbps.addvar(watchvar):
                    fbplist.add(funcbps)
        for funcbp in fbplist:
            self.bpnode_update(funcbp)

    def load_data(self):
        bptree = self.bptree
        watchtree = self.watchtree
        watchtree.clear()
        bptree.clear()
        bplist = self.dbginfo.bplist
        for _, funcbps in bplist.items():
            self.bptree_append(funcbps)

        watchvarlist = self.dbginfo.watchvarlist
        for _, var in watchvarlist.items():
            self.watchtree_append(var)

    def onActivated(self, text):
        # self.lbl.setText(text)
        print(text)

    def OnClose(self, form):
        print("regwatch {} closed".format(self.id))

    def onClicked(self, qmodelindex):
        item = self.bptree.currentItem()
        self.out(item)

    def onClicked2(self, qmodelindex):
        self.out(self.watchtree.currentItem())

    def out(self, item):
        text = 'Key=%s,value=%s' % (item.text(0), item.text(1))
        print(text)
        self.printout.setText(text)

    def onDClicked(self, qmodelindex):  # QModelIndex
        item = self.bptree.currentItem()
        parent = item.parent()
        if parent:
            addtext = item.text(1).strip()
            if re.search("^0x[\da-fA-F]{5,15}$", addtext):
                idc.Jump(int(addtext[2:], 16))
            else:
                text = item.text(0).strip()
                if text[0] == '+':
                    offset = int(text[1:], 16)
                    idc.Jump(parent.bps.addr + offset)

        else:
            idc.Jump(item.bps.addr)
        print('DClick Key=%s,value=%s' % (item.text(0), item.text(1)))

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)

    def showcall(self):
        dbginfo = self.dbginfo
        offset = dbginfo.offset
        for tid, callinfo in dbginfo.data_callinfo.items():
            callviewer.CallGraph("call view " + str(tid), callinfo, offset).Show()

    def clone(self):
        new_win = FuncTracer(self.dbginfo)
        new_win.Show()
        new_win.load_data()

    def bp_back(self):
        suffix = str(self.bpinput.text())
        if self.dbginfo.bp_backup(suffix):
            self.printout.setText("backup breakpoints{} success".format(suffix))

    def bp_restore(self):
        _reg_debug()
        suffix = str(self.bpinput.text())
        if self.dbginfo.bp_recover(True, suffix):
            self.printout.setText("restore breakpoints{} success".format(suffix))

    def callinfo_save(self):
        suffix = str(self.bpinput.text())
        if self.dbginfo.callinfo_backup(suffix):
            self.printout.setText("backup callinfo{} success".format(suffix))

    def callinfo_claer(self):
        self.dbginfo.callinfo_clear()

    def callinfo_load(self):
        _reg_debug()
        suffix = str(self.bpinput.text())
        calldata = self.dbginfo.callinfo_load(suffix, False)
        if calldata:
            offset = self.dbginfo.offset
            for tid, callinfo in calldata.items():
                callviewer.CallGraph(" ".join(["trace", str(tid), suffix]), callinfo, offset).Show()
        else:
            self.printout.setText("restore breakpoints{} failed".format(suffix))

    def enable_bps(self):
        enable = self.check_enable.isChecked()
        n = idc.get_bpt_qty()
        for i in range(n):
            bp = idc.get_bpt_ea(i)
            cfunc = idaapi.get_func(bp)
            if cfunc and cfunc.startEA == bp:
                idc.enable_bpt(bp, enable)

    def mode_switch(self):
        checkState = self.check_trace.checkState()
        if checkState == 2:
            config.mode_disbp_off()
            config.mode_trace_on()
            self.dbginfo.enabletrace = True
        elif checkState == 1:
            config.mode_disbp_on()
        else:
            config.mode_trace_off()
            self.dbginfo.enabletrace = False
