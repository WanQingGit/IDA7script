#coding=utf-8
from PyQt5 import QtCore, QtGui, QtWidgets
import  idaapi


class StructureBuilder(idaapi.PluginForm):
    def __init__(self):
        super(StructureBuilder, self).__init__()
        # self.structure_model = structure_model
        self.parent = None

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('Structure Builder')

        btn_finalize = QtWidgets.QPushButton("&Finalize")
        btn_disable = QtWidgets.QPushButton("&Disable")
        btn_enable = QtWidgets.QPushButton("&Enable")
        btn_origin = QtWidgets.QPushButton("&Origin")
        btn_array = QtWidgets.QPushButton("&Array")
        btn_pack = QtWidgets.QPushButton("&Pack")
        btn_unpack = QtWidgets.QPushButton("&Unpack")
        btn_remove = QtWidgets.QPushButton("&Remove")
        btn_resolve = QtWidgets.QPushButton("Resolve")
        btn_clear = QtWidgets.QPushButton("Clear")  # Clear button doesn't have shortcut because it can fuck up all work
        btn_recognize = QtWidgets.QPushButton("Recognize Shape")
        btn_recognize.setStyleSheet("QPushButton {width: 100px; height: 20px;}")

        btn_finalize.setShortcut("f")
        btn_disable.setShortcut("d")
        btn_enable.setShortcut("e")
        btn_origin.setShortcut("o")
        btn_array.setShortcut("a")
        btn_pack.setShortcut("p")
        btn_unpack.setShortcut("u")
        btn_remove.setShortcut("r")

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
        grid_box.addWidget(btn_finalize, 0, 0)
        grid_box.addWidget(btn_enable, 0, 1)
        grid_box.addWidget(btn_disable, 0, 2)
        grid_box.addWidget(btn_origin, 0, 3)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, 5)
        grid_box.addWidget(btn_array, 1, 0)
        grid_box.addWidget(btn_pack, 1, 1)
        grid_box.addWidget(btn_unpack, 1, 2)
        grid_box.addWidget(btn_remove, 1, 3)
        grid_box.addWidget(btn_resolve, 0, 4)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 1, 5)
        grid_box.addWidget(btn_recognize, 0, 6)
        grid_box.addWidget(btn_clear, 1, 6)

        vertical_box = QtWidgets.QVBoxLayout()

        treeView = QtWidgets.QTreeView(self.parent)
        treeView.setGeometry(QtCore.QRect(400, 150, 256, 192))
        treeView.setObjectName("treeView")

        tree = QtWidgets.QTreeWidget()
        self.tree=tree
        # 设置列数
        tree.setColumnCount(2)
        # 设置树形控件头部的标题
        tree.setHeaderLabels(['Key', 'Value'])

        # 设置根节点
        root = QtWidgets.QTreeWidgetItem(tree)
        root.setText(0, 'Root')
        # root.setIcon(0, QtWidgets.QIcon('./images/root.png'))

        # todo 优化2 设置根节点的背景颜色
        brush_red = QtGui.QBrush(QtCore.Qt.red)
        root.setBackground(0, brush_red)
        brush_blue = QtGui.QBrush(QtCore.Qt.blue)
        root.setBackground(1, brush_blue)

        # 设置树形控件的列的宽度
        tree.setColumnWidth(0, 150)

        # 设置子节点1
        child1 = QtWidgets.QTreeWidgetItem()
        child1.setText(0, 'child1')
        child1.setText(1, 'ios')
        # child1.setIcon(0, QtWidgets.QIcon('./images/IOS.png'))

        # todo 优化1 设置节点的状态
        child1.setCheckState(0, QtCore.Qt.Checked)

        root.addChild(child1)

        # 设置子节点2
        child2 = QtWidgets.QTreeWidgetItem(root)
        child2.setText(0, 'child2')
        child2.setText(1, '')
        # child2.setIcon(0, QtWidgets.QIcon('./images/android.png'))

        # 设置子节点3
        child3 = QtWidgets.QTreeWidgetItem(child2)
        child3.setText(0, 'child3')
        child3.setText(1, 'android')
        # child3.setIcon(0, QtWidgets.QIcon('./images/music.png'))

        # 加载根节点的所有属性与子控件
        tree.addTopLevelItem(root)

        # TODO 优化3 给节点添加响应事件
        tree.clicked.connect(self.onClicked)

        # 节点全部展开
        tree.expandAll()
        # self.parent.setCentralWidget(tree)




        combo = QtWidgets.QComboBox(self.parent)
        combo.addItem("Ubuntu")
        combo.addItem("Mandriva")
        combo.addItem("Fedora")
        combo.addItem("Arch")
        combo.addItem("Gentoo")
        combo.activated[str].connect(self.onActivated)


        # vertical_box.addWidget(struct_view)
        # vertical_box.addWidget(treeView)
        vertical_box.addWidget(tree)
        vertical_box.addWidget(combo)


        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

        # btn_finalize.clicked.connect(lambda: self.structure_model.finalize())
        # btn_disable.clicked.connect(lambda: self.structure_model.disable_rows(struct_view.selectedIndexes()))
        # btn_enable.clicked.connect(lambda: self.structure_model.enable_rows(struct_view.selectedIndexes()))
        # btn_origin.clicked.connect(lambda: self.structure_model.set_origin(struct_view.selectedIndexes()))
        # btn_array.clicked.connect(lambda: self.structure_model.make_array(struct_view.selectedIndexes()))
        # btn_pack.clicked.connect(lambda: self.structure_model.pack_substructure(struct_view.selectedIndexes()))
        # btn_unpack.clicked.connect(lambda: self.structure_model.unpack_substructure(struct_view.selectedIndexes()))
        # btn_remove.clicked.connect(lambda: self.structure_model.remove_items(struct_view.selectedIndexes()))
        # btn_resolve.clicked.connect(lambda: self.structure_model.resolve_types())
        # btn_clear.clicked.connect(lambda: self.structure_model.clear())
        # btn_recognize.clicked.connect(lambda: self.structure_model.recognize_shape(struct_view.selectedIndexes()))
        # struct_view.activated[QtCore.QModelIndex].connect(self.structure_model.activated)
        # self.structure_model.dataChanged.connect(struct_view.clearSelection)

    def onActivated(self, text):
        # self.lbl.setText(text)
        print(text)

    def OnClose(self, form):
        pass

    def onClicked(self, qmodeLindex):
        item = self.tree.currentItem()
        print('Key=%s,value=%s' % (item.text(0), item.text(1)))

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)