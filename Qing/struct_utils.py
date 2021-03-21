# idc.DbgQword(0x55BF95FA50)
from Qing.common import *
import re
import collections

VAR_BASE = 1
VAR_ARR = 2
VAR_PTR = 4
VAR_USR = 8


class BaseVar(BaseObj):

    def __init__(self, name, t, ea, np):
        super(BaseVar, self).__init__()
        self.name = name
        self.t = t
        self.ea = ea
        self.np = np
        self.valset = []
        self.values = []  # [val...]
        self.positions = []  # [pc...]

    def push_value(self, v):
        pc = Arch.ip()
        funcoffstr = idc.get_func_off_str(pc)
        self.positions.append(funcoffstr)
        valset = self.valset
        try:
            index = valset.index(v)
        except:
            index = len(valset)
            valset.append(v)
        self.values.append(index)

    def get(self, l):
        valset = self.valset
        values = self.values
        res = []
        for i in l:
            idx = values[i]
            res.append(valset[idx])
        return res

    def __repr__(self):
        return ":".join([self.name, str(self.ea)])


class WatchVar(BaseVar):

    def __init__(self, name, t, ea, np):
        super(WatchVar, self).__init__(name, t, ea, np)


class RegVar(BaseVar):
    # ea: reg or Offset from the SP register
    def __init__(self, name, t, ea, np):
        super(RegVar, self).__init__(name, t, ea, np)


class Member(object):

    def __init__(self, name=None):
        self.flag = 0
        self.tstr = None
        self.num = 1
        self.np = 0
        self.name = name

    def __repr__(self):
        return self.name


class Structure(object):

    def __init__(self, name, st=None):
        # self.ea = ea
        self.size = 0
        self.member = collections.OrderedDict()
        # self.st = st
        self.name = name
        self.update()

    def update(self):
        word = Arch.bits >> 3
        a = idc.get_struc_id(self.name)
        st = idaapi.get_struc(a)
        st_size = idaapi.get_struc_size(st)
        self.size = st_size
        offset = 0
        tinfo = idaapi.tinfo_t()
        while offset < st_size:
            member = idaapi.get_member(st, offset)
            if member is not None:
                _offset = offset
                size = idaapi.get_member_size(member)  # =member.eoff
                offset += size
                name = idaapi.get_member_name(member.id)
                if name.startswith("gap"):
                    continue
                flag = 0
                m = Member(name)
                idaapi.get_or_guess_member_tinfo(tinfo, member)
                tstr = get_typestr(tinfo)
                typestr = tstr
                res = re.search("A(\d+)$", typestr)
                if res:
                    flag |= VAR_ARR
                    count = int(res.groups()[0])
                    size /= count
                    m.num = count
                    length = len(res.group())
                    typestr = typestr[:-length]
                else:
                    res = re.search("P+$", typestr)
                    if res:
                        flag |= VAR_PTR
                        length = len(res.group())
                        m.np = length
                        typestr = typestr[:-length]
                    else:
                        m.np = 0
                if typestr in basec or size < word:
                    flag |= VAR_BASE
                else:
                    flag |= VAR_USR
                m.flag = flag
                m.tstr = typestr
                s = name.split("_")
                if len(s) == 2:
                    suffix = "%X" % _offset
                    if s[0] != tstr and s[1] == suffix:
                        s[0] = tstr
                        s[1] = suffix
                        name = "_".join(s)
                        idaapi.set_member_name(st, _offset, name)
                        m.name = name
                self.add_member(_offset, m)
            else:
                offset = (offset + 4) >> 2 << 2

    def add_member(self, offset, m):
        self.member[offset] = m

    def __repr__(self):
        return self.name


halfword = Arch.bits >> 4
align = ((1 << 32) - 1) >> (halfword / 2) << (halfword / 2)


def st_rename_auto(st, tinfo=None):
    if tinfo is None:
        tinfo = idaapi.tinfo_t()
    st_size = idaapi.get_struc_size(st)
    offset = 0
    while offset < st_size:
        member = idaapi.get_member(st, offset)
        if member is None:
            offset = (offset + halfword) & align
            continue
        _offset = offset
        width = idaapi.get_member_size(member)  # =member.eoff
        offset += width
        name = idaapi.get_member_name(member.id)
        idaapi.get_or_guess_member_tinfo(tinfo, member)
        # idaapi.get_next_member_idx()
        s = name.split("_")
        if len(s) != 2 or name.startswith("gap"):
            continue
        name = get_typestr(tinfo)
        try:
            if int(s[1], 16) != _offset:
                print("offset is not equel,struct member {},cout {},but {}".format("_".join(s), offset, s[1]))
                continue
        except Exception, e:
            print("the format of name should be type_offset  except offset but get {}".format(s[1]))
        if name == s[0]:
            continue
        name = name + "_" + s[1]
        idaapi.set_member_name(st, _offset, name)


def st_rename(stname, tinfo=None):  # (idx, sid, name)
    a = idc.get_struc_id(stname)
    st = idaapi.get_struc(a)
    if st:
        st_rename_auto(st, tinfo)


def st_merge(stname1, stname2):
    tinfo = idaapi.tinfo_t()
    a = idc.get_struc_id(stname1)
    st1 = idaapi.get_struc(a)
    a = idc.get_struc_id(stname2)
    st2 = idaapi.get_struc(a)
    st1_size = idaapi.get_struc_size(st1)
    st2_size = idaapi.get_struc_size(st2)
    offset = 0
    maxsize, minsize = (st1_size, st2_size) if st1_size > st2_size else (st2_size, st1_size)
    while offset < minsize:
        member1 = idaapi.get_member(st1, offset)
        member2 = idaapi.get_member(st2, offset)
        if member1 is None:
            member=member2
        elif member2 is None:
            member=member1
        else:
            idaapi.get_or_guess_member_tinfo(tinfo, member)
            get_typestr(member1.t)
            pass
