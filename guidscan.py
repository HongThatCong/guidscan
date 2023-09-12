# Org code: https://github.com/you0708/ida/tree/master/idapython_tools/findguid
# Lint, fix bugs and mod by HTC @VCS
# pylint: disable=C0301,C0103,C0111

from __future__ import print_function

import os
import binascii
import struct
import traceback

import idc
import idaapi

GUID_LIST_DIR = os.path.dirname(__file__)
GUID_LIST = []

# [name, prefix, filepath]^
GUID_LIST.append(['Class ID', 'CLSID_', os.path.join(GUID_LIST_DIR, 'classes.txt')])
GUID_LIST.append(['Interface ID', 'IID_', os.path.join(GUID_LIST_DIR, 'interfaces.txt')])
GUID_LIST.append(['Folder ID', '', os.path.join(GUID_LIST_DIR, 'folder.txt')])  # already have prefix FOLDERID
GUID_LIST.append(['Media Type', 'GUID_', os.path.join(GUID_LIST_DIR, 'media.txt')])

CHECK_DUPLICATE = True
GUID_DICT = {}


def get_guid_tid():
    tid = idc.get_struc_id('GUID')
    if tid == idaapi.BADADDR:
        tid = idc.import_type(-1, "GUID")
        if tid == idc.BADADDR:
            print("[*] create GUID struct")
            tid = idc.add_struc(idc.BADADDR, 'GUID', 0)
            idc.add_struc_member(tid, 'Data1', 0x0, idc.FF_DWORD | idc.FF_DATA, -1, 4)
            idc.add_struc_member(tid, 'Data2', 0x4, idc.FF_WORD | idc.FF_DATA, -1, 2)
            idc.add_struc_member(tid, 'Data3', 0x6, idc.FF_WORD | idc.FF_DATA, -1, 2)
            idc.add_struc_member(tid, 'Data4', 0x8, idc.FF_BYTE | idc.FF_DATA, -1, 8)
    return tid


def make_binary_pattern(guid):
    # sample guid: 0F87369F-A4E5-4CFC-BD3E-73E6154572DD
    tmp = guid.split('-')
    data = b''
    data += struct.pack('<L', int(tmp[0], 16))
    data += struct.pack('<H', int(tmp[1], 16))
    data += struct.pack('<H', int(tmp[2], 16))
    data += struct.pack('>H', int(tmp[3], 16))
    data += binascii.a2b_hex(tmp[4])

    binary_pattern = ' '.join(map(lambda x: format(x if isinstance(x, int) else ord(x), '02x'), list(data)))
    return binary_pattern


def main():
    idaapi.msg_clear()
    idaapi.show_wait_box("Please wait...")

    try:
        get_guid_tid()

        # HTC - force load COM Helper plugin and run Scan CLSIDs from registry and clsid.cfg file
        # IDA COM Helper plugin will install idb hook and auto add Interfaces + Vtbls for GUIDs found
        # with type info in the current idb's type libraries (*.til)
        print('[*] scan CLSIDs with IDA COM Helper plugin...')
        COM_Helper = 'comhelper64' if idaapi.cvar.inf.is_64bit() else 'comhelper'
        if not idaapi.load_and_run_plugin(COM_Helper, 1):   # run(1) is scan CLSIDs and turn on auto
            print('[*] load and run COM Helper plugin failed')

        print('[*] scan with addition GUIDs in txt files')
        for type_name, type_prefix, filepath in GUID_LIST:
            if idaapi.user_cancelled():
                break

            smsg = f'[*] scanning with file {filepath}, type {type_name}'
            print(smsg)
            idaapi.replace_wait_box(smsg)

            with open(filepath, 'r', encoding="utf8") as fp:
                lines = fp.readlines()

            for line in lines:
                if idaapi.user_cancelled():
                    break

                line = line.strip()
                if not line:
                    continue

                if line[0] in ('#', ';', '//'):   # comment
                    continue

                guid, guid_name = line.split(' ')
                if not guid or not guid_name:
                    print(f"Data error at line: '{line}' - file: '{filepath}'")
                    continue

                guid = guid.upper()

                if CHECK_DUPLICATE:
                    if guid not in GUID_DICT:
                        GUID_DICT[guid] = [guid_name, filepath]
                    else:
                        print(f"Duplicate GUID: {guid}\n\tOld: {GUID_DICT[guid][0]} - file: {GUID_DICT[guid][1]}"
                              f"\n\tNew: {guid_name} - file: {filepath}")

                guid_name = type_prefix + guid_name
                binary_pattern = make_binary_pattern(guid)

                smsg = f'scanning {guid_name}'
                idaapi.replace_wait_box(smsg)

                ea = idaapi.cvar.inf.min_ea
                while True:
                    ea = idaapi.find_binary(ea, idaapi.cvar.inf.max_ea, binary_pattern,
                                            16, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
                    if ea == idc.BADADDR:
                        break

                    old_name = idc.get_name(ea)
                    if not old_name:
                        # create new name
                        idc.del_items(ea, idc.DELIT_SIMPLE, 16)
                        idc.create_struct(ea, -1, "GUID")
                        idc.set_name(ea, guid_name, idaapi.SN_FORCE)
                        idc.set_cmt(ea, f"{{{guid}}}", 0)
                    elif old_name != guid_name:
                        idc.set_cmt(ea, f"{guid_name} = {{{guid}}}", 0)

                    print(f"[*] 0x{ea:X}: {guid_name}")

                    if idaapi.user_cancelled():
                        break

        print("[*] aborted" if idaapi.user_cancelled() else "[*] finished")

    except:
        traceback.print_exc()

    finally:
        idaapi.hide_wait_box()


if __name__ == "__main__":
    main()
