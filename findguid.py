# Org code: https://github.com/you0708/ida/tree/master/idapython_tools/findguid
# Lint, fix bugs and mod by HTC - VinCSS (a member of Vingroup)
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
GUID_LIST.append(['Folder ID', 'IID_', os.path.join(GUID_LIST_DIR, 'folder.txt')])
GUID_LIST.append(['Media Type', 'IID_', os.path.join(GUID_LIST_DIR, 'media.txt')])

def get_guid_tid():
    tid = idc.get_struc_id('GUID')
    if tid == idaapi.BADADDR:
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
    data = ''
    data += struct.pack('<L', int(tmp[0], 16))
    data += struct.pack('<H', int(tmp[1], 16))
    data += struct.pack('<H', int(tmp[2], 16))
    data += struct.pack('>H', int(tmp[3], 16))
    data += binascii.a2b_hex(tmp[4])

    binary_pattern = ' '.join(map(binascii.b2a_hex, list(data)))
    return binary_pattern

def main():
    idaapi.msg_clear()
    idaapi.show_wait_box("Please wait...")

    try:
        get_guid_tid()

        # HTC - force load COM Helper plugi and run Scan CLSIDs from registry and clsid.cfg file
        print('[*] scan CLSIDs with IDA COM Helper plugin...')
        COM_Helper = 'comhelper64' if idc.__EA64__ else 'comhelper'
        if not idaapi.load_and_run_plugin(COM_Helper, 1):   # run(1) is scan CLSIDs
            print('[*] load and run COM Helper plugin failed')

        print('[*] scan CLSIDs with addition GUID txt files')
        for type_name, type_prefix, filepath in GUID_LIST:
            if idaapi.user_cancelled():
                break

            smsg = '[*] scanning with file %s, type %s' % (filepath, type_name)
            print(smsg)
            idaapi.replace_wait_box(smsg)

            with open(filepath, 'r') as fp:
                lines = fp.readlines()

            for line in lines:
                if idaapi.user_cancelled():
                    break

                line = line.strip()
                if not line:
                    continue

                guid, guid_name = line.split(' ')
                guid_name = type_prefix + guid_name
                binary_pattern = make_binary_pattern(guid)

                smsg = 'scanning %s' % guid_name
                idaapi.replace_wait_box(smsg)

                ea = 0
                while True:
                    ea = idc.find_binary(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, binary_pattern)
                    if ea == idc.BADADDR:
                        break

                    idc.del_items(ea, idc.DELIT_SIMPLE, 16)
                    idc.create_struct(ea, -1, "GUID")
                    idc.set_name(ea, guid_name, idaapi.SN_NOWARN | idaapi.SN_FORCE)
                    print("[*] 0x{:X}: {}".format(ea, guid_name))

                    if idaapi.user_cancelled():
                        break


        print("[*] aborted" if idaapi.user_cancelled() else "[*] finished")

    except:
        traceback.print_exc()

    finally:
        idaapi.hide_wait_box()

if __name__ == "__main__":
    main()
