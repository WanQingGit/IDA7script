import pydevd_pycharm

DBG_INFO = 3
DBG_WARN = 2
DBG_ERR = 1


class Debugger(object):

    def __init__(self, trace=True, level=DBG_INFO, suspend=True):
        self.trace = trace
        self.level = level
        self.suspend = suspend

    def __call__(self, *args, **kwargs):
        if self.trace:
            try:
                self.info("dbg_called")
                pydevd_pycharm.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True,
                                        suspend=self.suspend)
            except Exception as e:
                print(e)

    def debug(self):
        try:
            self.info("debug_suspend")
            pydevd_pycharm.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True,
                                    suspend=True)  # patch_multiprocessing=True,
        except Exception as e:
            print(e)

    def info(self, *msg):
        if self.level >= DBG_INFO:
            print(msg)

    def warn(self, *msg):
        if self.level >= DBG_WARN:
            print(msg)

    def err(self, *msg):
        if self.level >= DBG_ERR:
            print(msg)

    def on(self):
        self.trace = True
        self.level = DBG_INFO

    def off(self):
        self.trace = False
        self.level = DBG_WARN

    # sys.path.append(r"D:\app\sts-4.4.0.RELEASE\plugins\org.python.pydev.core_7.3.0.201908161924\pysrc")
    # import pydevd
    # pydevd.settrace('127.0.0.1', port=5678, stdoutToServer=True, stderrToServer=True)
    # pydevd_pycharm.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True,
    #                         patch_multiprocessing=True)
