# pylint: disable=C0301,C0103,C0111

from __future__ import print_function

import os
import idaapi
import idc
import ida_funcs

DISPID = \
{
    250: "DISPID_BEFORENAVIGATE2",
    252: "DISPID_NAVIGATECOMPLETE2",
    253: "DISPID_ONQUIT",
    259: "DISPID_DOCUMENTCOMPLETE"
}

def loadDISPID():
    events_txt = os.path.join(os.path.dirname(__file__), "DWebBrowserEvents.txt")
    print(events_txt)
    for line in file(events_txt, "r"):
        line = line.split(" ")
        DISPID[int(line[1])] = line[0]

def bho_invoke(ea, id, idName):
    funcStart = ea
    funcEnd = idc.get_func_attr(ea, idc.FUNCATTR_END)
    while True:
        ea, _ = idc.find_imm(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, id)
        if ea == idc.BADADDR or ea > funcEnd:
            break

        if idc.print_insn_mnem(ea) == "cmp":
            print("0x%X: found %s" %(ea, idName))
            idc.set_cmt(ea, idName, 0)

        ea += 1 # Find next


def main():
    idaapi.msg_clear()
    idaapi.show_wait_box("Please wait...")

    loadDISPID()

    ea = 0
    places = {}
    for k, v in DISPID.iteritems():
        idaapi.replace_wait_box("Searching for %d %s" % (k, v))
        while True:
            ea, _ = idc.find_imm(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, k)
            if ea == idc.BADADDR:
                break

            func = ida_funcs.get_func(ea)
            if not func:
                ea += 1
                continue

            funcStart = func.start_ea
            if not places.has_key(funcStart):
                places[funcStart] = 0
            else:
                places[funcStart] += 1

            bho_invoke(funcStart, k, v)

        ea = 0

    lmax = 0
    invokeAddr = 0
    for k, v in places.iteritems():
        if k != 0 and lmax < v:
            lmax = v
            invokeAddr = k
        print("Potential Invoke function 0x%X:  appearance %d" % (k, v))

    print("Suggested address of Invoke function: 0x%X " % invokeAddr)

    idaapi.hide_wait_box()

if __name__ == "__main__":
    main()
