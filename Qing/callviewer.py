from Qing.common import *
from Qing import chooser

graph_dbg = Debugger()
graph_dbg.off()


class CallNode(object):

    def __init__(self, afn):
        self.afn = afn
        # self.name = idc.GetFuncOffset(afn)


class CallGraph(idaapi.GraphViewer):

    def __init__(self, title, fninfo, offset):
        GraphViewer.__init__(self, title, True)
        self.nodes = {}
        self.refresh = True
        self.fninfo = fninfo
        self.offset = offset
        # warning: this won't work after code relocation !

    def GetNode(self, afn):
        nodes = self.nodes
        if afn in nodes:
            return nodes[afn]
        else:
            nodefn = CallNode(afn)
            name = idc.GetFuncOffset(afn + self.offset)
            if not name:
                nodefn.name = "error_" + hex(afn)
            else:
                nodefn.name = name
            nodefn.ncalled = str(self.fninfo[afn].ncalled)
            nodeID = self.AddNode(nodefn)
            nodes[afn] = nodeID
            return nodeID

    def OnRefresh(self):
        graph_dbg()
        if not self.refresh:
            return True
        self.Clear()
        self.nodes.clear()
        for afn, fninfo in self.fninfo.items():
            calllist = fninfo.calllist
            if calllist:
                nodesrc = self.GetNode(afn)
                for ea, off in calllist.items():
                    nodedst = self.GetNode(ea)
                    self.AddEdge(nodesrc, nodedst)
        self.refresh = False
        return True

    def OnGetText(self, node_id):
        # graph_dbg()
        node = self[node_id]
        return node.name + " | " + node.ncalled

    def OnSelect(self, node_id):
        """
        Triggered when a node is being selected
        @return: Return True to allow the node to be selected or False to disallow node selection change
        """
        # allow selection change
        print("OnSelect", node_id)
        return True

    def getrows(self, afn):  # calllist, calledlist,
        offset = self.offset
        rows = []
        if afn not in self.fninfo:
            return None
        funcinfo = self.fninfo[afn]

        for ea, callset in funcinfo.calllist.items():
            fname = idc.get_func_off_str(ea + offset)
            for off in callset:
                aoff = off + offset
                text = idc.GetDisasm(aoff)
                address = idc.get_func_off_str(aoff)
                ncall = self.fninfo[ea].calledlist[off]
                rows.append([fname, "call", address, hex(aoff)[:-1], str(ncall), text])

        for off, ncall in funcinfo.calledlist.items():
            aoff = off + offset
            offstr = idc.get_func_off_str(aoff)
            fname = offstr.split("+")[0]
            text = idc.GetDisasm(aoff)
            rows.append([fname, "called", offstr, hex(aoff)[:-1], str(ncall), text])
        return rows

    def OnClick(self, node_id):
        node = self[node_id]
        chooser.choosershow(self.getrows(node.afn))
        # print("OnClick", node_id)
        return True

    def OnDblClick(self, node_id):
        node = self[node_id]
        # idc.Jump(node.afn)
        print("OnDblClick", str(node.afn))
        return True

    def OnHint(self, node_id):
        node = self[node_id]
        print("0x%X" % (node.afn + self.offset))
        return "ncall " + node.ncalled
