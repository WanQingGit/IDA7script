class DebugMode(object):
    NORMAL = 0
    TRACE = 1
    MONITOR = 2
    REGWATCH = 4
    VIOLENCE = 8
    DISBP = 16


DEBUG_MODE = DebugMode.NORMAL
USE_DEBUG = False
import os

DBGINFO_SAVE_PATH = os.getcwd() + "\\dbginfo-data"


def mode2monitor():
    global DEBUG_MODE
    DEBUG_MODE = DebugMode.MONITOR


def mode2trace():
    global DEBUG_MODE
    DEBUG_MODE = DebugMode.TRACE


def mode2normal():
    global DEBUG_MODE
    DEBUG_MODE = DebugMode.NORMAL


def mode_disbp_on():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE | DebugMode.DISBP


def mode_disbp_off():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE ^ DebugMode.DISBP


def mode_trace_on():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE | DebugMode.TRACE


def mode_trace_off():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE ^ DebugMode.TRACE


def mode_violence_on():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE | DebugMode.VIOLENCE


def mode_violence_off():
    global DEBUG_MODE
    DEBUG_MODE = DEBUG_MODE ^ DebugMode.VIOLENCE
