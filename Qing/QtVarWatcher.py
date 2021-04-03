# coding=utf-8
from PyQt5 import QtCore, QtGui, QtWidgets
import idaapi, idc
from Qing.common import WordObj
from Qing import config, common
from Qing.config import DebugMode
import re
import Qing.func_utils as func_utils
from Qing.struct_utils import WatchVar
from Qing.QtBase import QtUiShow

_watch_debug = common.Debugger()
regs = set()
for _r in idaapi.dbg_get_registers():
    regs.add(_r[0])
_watch_debug.off()


class VarWatcher(QtUiShow):
    def __init__(self, dbginfo):
        super(VarWatcher, self).__init__()
        self.dbginfo = dbginfo
        self.funcargs = dbginfo.funcarg
        self.watchfn = {}
        self.funclist = {}
        # self.parent = None
        self.bptree = None
        self.watchtree = None
        self.bpinput = None
        self.addrinput = None
        self.printout = None
        self.id = VarWatcher.ninstance
        self.bplistback = None
        VarWatcher.ninstance = self.id + 1

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            # "QPushButton {width: 50px; height: 20px;}"
            "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.setWindowTitle('VarWatcher-' + str(self.id))

        btn_Clone = QtWidgets.QPushButton("&Clone")
        btn_Clone.clicked.connect(self.clone)
        btn_update = QtWidgets.QPushButton("&Update")
        btn_update.clicked.connect(self.load_data)
        btn_diff = QtWidgets.QPushButton("&Diff")
        btn_diff.clicked.connect(self.var_diff)
        btn_normal = QtWidgets.QPushButton("&Normal")
        btn_normal.clicked.connect(config.mode2normal)
        btn_trace = QtWidgets.QPushButton("&Trace")
        btn_trace.clicked.connect(config.mode2trace)
        btn_monitor = QtWidgets.QPushButton("Monitor")
        btn_monitor.clicked.connect(config.mode2monitor)
        check_violence = QtWidgets.QCheckBox("Violence")
        check_violence.stateChanged.connect(self.violence_mode)
        self.check_violence = check_violence
        text_out = QtWidgets.QLineEdit()
        self.printout = text_out
        btn_addall = QtWidgets.QPushButton("Load All Breakpoints")
        btn_addall.clicked.connect(self.load_all_bps)
        # btn_recognize.setStyleSheet("QPushButton {width: 100px; height: 20px;}")

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
        idx = 0
        grid_box.addWidget(btn_Clone, 0, idx)
        idx += 1
        grid_box.addWidget(btn_update, 0, idx)
        idx += 1
        grid_box.addWidget(btn_diff, 0, idx)
        idx += 1
        grid_box.addWidget(btn_normal, 0, idx)
        idx += 1
        grid_box.addWidget(btn_trace, 0, idx)
        idx += 1
        grid_box.addWidget(btn_monitor, 0, idx)
        idx += 1
        grid_box.addWidget(check_violence, 0, idx)
        idx += 1
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, idx)
        idx += 1

        grid_box.addWidget(text_out, 0, idx)
        idx += 1
        grid_box.addWidget(btn_addall, 0, idx)

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
        btndel.clicked.connect(self.del_bpnode)
        fneditlayout.addWidget(btndel)

        breakbtn = QtWidgets.QPushButton("&[un]break")
        breakbtn.clicked.connect(self.break_switch)
        fneditlayout.addWidget(breakbtn)

        btnaddright = QtWidgets.QPushButton("&add...")
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
        addrinput.setPlaceholderText("addr type np name")
        watcheditlayout.addWidget(addrinput)
        btnwatch = QtWidgets.QPushButton("&watch")
        btnwatch.clicked.connect(self.add_var)
        watcheditlayout.addWidget(btnwatch)

        spacer = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding)
        watcheditlayout.addSpacerItem(spacer)
        takebtn = QtWidgets.QPushButton("&take")
        takebtn.clicked.connect(self.read_var)
        watcheditlayout.addWidget(takebtn)
        btnunattach = QtWidgets.QPushButton("&unattach")
        btnunattach.clicked.connect(self.unattach)
        watcheditlayout.addWidget(btnunattach)

        btndel = QtWidgets.QPushButton("&del")
        btndel.clicked.connect(self.del_var)
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
        try:
            text = self.addrinput.text().encode('utf-8').strip()
            vals = re.sub("\\s+", " ", text).split(" ")
            lenv = len(vals)
            if lenv == 1:
                name = vals[0]
                vals = name.split("_")
                if len(vals) != 2:
                    return
                addr = vals[0]
                name = vals[1] + "_" + vals[0]  # [-4:-1]
                tp = vals[1]
                t = re.sub("P+$", "", tp)
                np = len(tp) - len(t)
            elif lenv != 4:
                return
            else:
                t = vals[1]
                np = int(vals[2])
                name = vals[3]
                addr = vals[0]
            if addr.upper() in regs:
                var = self.dbginfo.add_reg_var(addr, name, t, np)
            elif addr[0] == 's':
                var = self.dbginfo.add_reg_var(int(addr[1:], 16), name, t, np + 1)
            else:
                ea = int(addr, 16)
                ea = WordObj(ea)
                if ea.ref is None:
                    return
                var = self.dbginfo.add_watch_var(ea, name, t, np)
            if var is not None:
                self.watchtree_append(var)
        except Exception as e:
            self.addrinput.setText("")
            self.printout.setText(str(e))

    def read_var(self):
        item = self.watchtree.currentItem()
        if item.parent():
            return
        var = item.var
        if self.dbginfo.read_var(var):
            self.watchnode_update(var)

    def var_diff(self):
        _watch_debug()
        try:
            items = self.watchtree.selectedItems()
            if len(items) == 2:
                if VarWatcher.out_diff(items):
                    return
            items = self.watchtree.selectedItems()
            if len(items) == 2:
                VarWatcher.out_diff(items)
                return
        except Exception as e:
            self.printout.setText(str(e))

    @staticmethod
    def out_diff(items):
        itemA = items[0]
        parentA = itemA.parent()
        itemB = items[1]
        parentB = itemB.parent()
        if parentA != parentB:
            return False
        if not hasattr(parentA, "var"):
            return False
        var = parentA.var
        idxA = int(itemA.text(0))
        idxB = int(itemB.text(0))
        vals = var.get([idxA, idxB])
        print(common.dict_diff(vals[0], vals[1]))
        return True

    def del_var(self):
        item = self.watchtree.currentItem()
        if item.parent():
            return
        var = item.var
        if isinstance(var, WatchVar):
            self.dbginfo.del_watch_var(var.ea)
        else:
            self.dbginfo.del_reg_var(var.name)
        watchtree = self.watchtree
        root = watchtree.invisibleRootItem()
        root.removeChild(item)

    def add_bp(self):
        _watch_debug()
        text = self.bpinput.text().encode('utf-8').strip()
        if len(text) > 5:
            ea = int(text, 16)
        else:
            ea = idc.get_screen_ea()
        dbginfo = self.dbginfo
        res = dbginfo.addbp2(ea)
        if res:
            self.bpnode_update(res)
            return True
        return False

    def del_bpnode(self):
        _watch_debug()
        dbginfo = self.dbginfo
        bptree = self.bptree
        # item = bptree.currentItem()
        for item in bptree.selectedItems():
            parent = item.parent()
            if parent:
                if hasattr(parent, "bps"):
                    funcbps = parent.bps
                    dbginfo.delbp2(funcbps.addr, item.offset)
                elif hasattr(parent, "offset"):
                    root = parent.parent()
                    funcbps = root.bps
                    offset = parent.offset
                    key = item.text(1)
                    if key[:2].upper() == '0X':
                        key = int(key[2:], 16)
                    dbginfo.delbp2(funcbps.addr, offset, key)
                else:
                    continue
                parent.removeChild(item)
            else:
                funcbps = item.bps
                self.dbginfo.delfuncbps(funcbps)
                root = bptree.invisibleRootItem()
                root.removeChild(item)

    def add_from_watchvar(self):
        bptree = self.bptree
        watchtree = self.watchtree
        bpItem = bptree.currentItem()
        if not hasattr(bpItem, "offset"):
            return
        bpparent = bpItem.parent()
        funcbps = bpparent.bps
        watchItems = watchtree.selectedItems()
        update = False
        for watchItem in watchItems:
            # watchItem = watchtree.currentItem()
            if watchItem.parent():
                continue
            if funcbps.addvar(watchItem.var, bpItem.offset):
                update = True
        if update:
            self.bpnode_update(funcbps)

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
                node.setBackground(0, VarWatcher.brush_white)
            else:
                node.setBackground(0, VarWatcher.brush_white)
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
            for ea, varinfo in varlist.items():
                varroot = QtWidgets.QTreeWidgetItem(node)
                var = varinfo['var']
                values = var.values
                valset = var.valset
                varname = var.name
                nums = varinfo['indexs']
                varroot.setText(0, varname + " " + str(len(nums)))
                varroot.setText(1, str(var.ea))
                varroot.var = var
                prevValue = -1
                for i in nums:
                    idx = values[i]
                    child = QtWidgets.QTreeWidgetItem(varroot)
                    child.setText(0, str(i))
                    if idx != prevValue:
                        QtUiShow.appendchild(child, valset[idx])
                        # child.setBackground(1, VarWatcher.brush_dark)
                        prevValue = idx
        return root

    def watchtree_append(self, watchvar):
        watchtree = self.watchtree
        root = QtWidgets.QTreeWidgetItem(watchtree)
        varname = watchvar.name
        root.var = watchvar
        watchvar[self.id]["watchnode"] = root
        values = watchvar.values
        valset = watchvar.valset
        positons = watchvar.positions
        lenv = len(values)
        prevValue = -1
        root.setText(0, varname + " " + str(len(valset)) + " " + str(lenv))
        root.setText(1, str(watchvar.ea))
        for i in range(lenv):
            idx = values[i]
            child = QtWidgets.QTreeWidgetItem(root)
            child.setText(0, str(i))
            child.setText(1, positons[i])
            if idx != prevValue:
                # child.setBackground(1, VarWatcher.brush_red)
                QtUiShow.appendchild(child, valset[idx])
                prevValue = idx

    def unattach(self):
        _watch_debug()
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
                dbginfo.delbp2(ea, offset, var.ea)
            else:
                continue

    def attach_bp_selected(self):
        _watch_debug()
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

    def load_all_bps(self):
        dbginfo = self.dbginfo
        bpupdate = set()
        for i in range(idc.GetBptQty()):
            bp = idc.GetBptEA(i)
            res = dbginfo.addbp2(bp)
            if res:
                bpupdate.add(res)
        for funcbp in bpupdate:
            self.bpnode_update(funcbp)

    def bptree_reload(self):
        bptree = self.bptree
        bptree.clear()
        bplist = self.dbginfo.bplist
        for _, funcbps in bplist.items():
            self.bptree_append(funcbps)

    def watchtree_reload(self):
        watchtree = self.watchtree
        watchtree.clear()
        watchvarlist = self.dbginfo.watchvarlist
        for _, var in watchvarlist.items():
            self.watchtree_append(var)
        regvarlist = self.dbginfo.regvarlist
        for _, var in regvarlist.items():
            self.watchtree_append(var)

    def load_data(self):
        self.bptree_reload()
        self.watchtree_reload()

    def break_switch(self):
        _watch_debug()
        bptree = self.bptree
        for item in bptree.selectedItems():
            parent = item.parent()
            if parent:
                if hasattr(parent, "bps"):
                    funcbps = parent.bps
                    bp = funcbps.addr + item.offset
                    state = idc.check_bpt(bp)
                    if state == 1 or state == 0:
                        idc.enable_bpt(bp, 1 - state)
                else:
                    continue
            else:
                funcbps = item.bps
                addr = funcbps.addr
                for offset, _ in funcbps.bps.items():
                    bpea = offset + addr
                    state = idc.check_bpt(bpea)
                    if state != -1:
                        idc.enable_bpt(bpea, 1 - state)

    def onActivated(self, text):
        # self.lbl.setText(text)
        print(text)

    def OnClose(self, form):
        print("watchshow {} closed".format(self.id))

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
        # self.load_data()
        return idaapi.PluginForm.Show(self, caption, options=options)

    def clone(self):
        new_win = VarWatcher(self.dbginfo)
        new_win.Show()
        new_win.load_data()

    def load_and_add(self, var):
        dbginfo = self.dbginfo
        bpupdate = set()
        for i in range(idc.GetBptQty()):
            bp = idc.GetBptEA(i)
            res = dbginfo.addbp2(bp)
            if res:
                bpupdate.add(res)
        for funcbp in bpupdate:
            self.bpnode_update(funcbp)

    def violence_mode(self):
        _watch_debug()
        if self.check_violence.isChecked():
            if config.DEBUG_MODE & DebugMode.VIOLENCE:
                return
            if self.dbginfo.bp_backup("violence"):
                self.printout.setText("backup breakpoints success")
                func_utils.addBpFuncHead()
                config.mode_violence_on()
            else:
                self.printout.setText("backup breakpoints fail")
                self.check_violence.setChecked(False)
        else:
            if not config.DEBUG_MODE & DebugMode.VIOLENCE:
                return
            if self.dbginfo.bp_recover(True, "violence"):
                self.printout.setText("restore breakpoints success")
                config.mode_violence_off()
            else:
                self.check_violence.setChecked(True)
                self.printout.setText("restore breakpoints fail")
