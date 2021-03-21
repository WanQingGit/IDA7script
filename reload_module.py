import sys

sys.path.append(r"S:\data\workspace\c\IDA7")
from Qing import common, struct_utils, func_utils, dbginfo, QtBase, QtArgAnalyzer, QtTracer, QtVarWatcher

reload(common)
reload(struct_utils)
reload(func_utils)
reload(dbginfo)
reload(QtBase)
reload(QtArgAnalyzer)
reload(QtVarWatcher)
reload(QtTracer)
SCRIPT_LOAD=True
if "debughook" in dir():
    debughook.dbginfo = None
