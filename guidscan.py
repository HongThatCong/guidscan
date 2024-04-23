# Org code: https://github.com/you0708/ida/tree/master/idapython_tools/findguid
# Lint, fix bugs and mod by HTC @VCS
# pylint: disable=C0301,C0103,C0111

import os
import binascii
import struct
import traceback
from collections import namedtuple

import idc
import idaapi
import idautils

GUID_DIR = os.path.dirname(__file__)
GUID_FILES = []

# [name, prefix, filepath]^
GUID_FILES.append(["Class ID", "CLSID_", os.path.join(GUID_DIR, "clsids.txt")])
GUID_FILES.append(["Interface ID", "IID_", os.path.join(GUID_DIR, "iids.txt")])
GUID_FILES.append(["GUID Type", "GUID_", os.path.join(GUID_DIR, "guids.txt")])

# unclassified.txt - uncomment for testing and/or extra scan
# GUID_FILES.append(["Unclassified GUID", "", os.path.join(GUID_DIR, "unclassified.txt")])

GUID_LOADED: dict = {}
SCAN_RESULT: set = set()
RESULT_CHOOSER = None


def create_guid_struct():
    tid = idc.get_struc_id("GUID")
    if tid == idaapi.BADADDR:
        tid = idc.import_type(-1, "GUID")
        if tid == idc.BADADDR:
            print("[*] create GUID struct")
            tid = idc.add_struc(idc.BADADDR, "GUID", 0)
            idc.add_struc_member(tid, "Data1", 0x0, idc.FF_DWORD | idc.FF_DATA, -1, 4)
            idc.add_struc_member(tid, "Data2", 0x4, idc.FF_WORD | idc.FF_DATA, -1, 2)
            idc.add_struc_member(tid, "Data3", 0x6, idc.FF_WORD | idc.FF_DATA, -1, 2)
            idc.add_struc_member(tid, "Data4", 0x8, idc.FF_BYTE | idc.FF_DATA, -1, 8)
    return tid


def make_binary_pattern(guid):
    # The Old New Thing: https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221
    # Wikipedia: https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding
    # Variant 2 UUIDs, historically used in Microsoft's COM/OLE libraries, use a little-endian format,
    # but appear mixed-endian with the first three components of the UUID as little-endian and last
    # two big-endian, due to the missing byte dashes when formatted as a string.
    # For example: 00112233-4455-6677-8899-aabbccddeeff is encoded
    # as the little-endian bytes: 33 22 11 00, 55 44, 77 66, 88 99, aa bb cc dd ee ff

    try:
        tmp = guid.split("-")
        data = b""
        data += struct.pack("<L", int(tmp[0], 16))
        data += struct.pack("<H", int(tmp[1], 16))
        data += struct.pack("<H", int(tmp[2], 16))
        data += struct.pack(">H", int(tmp[3], 16))
        data += binascii.a2b_hex(tmp[4])

        binary_pattern = " ".join(f"{x:02X}" for x in data)
        return binary_pattern
    except:
        traceback.print_exc()
        return None


def set_cmt_ex(ea, new_cmt, repeat=0):
    old_cmt = idc.get_cmt(ea, repeat)
    if not old_cmt:
        idc.set_cmt(ea, new_cmt, repeat)
    elif new_cmt not in old_cmt:
        if not old_cmt.endswith("\n"):
            old_cmt += "\n"
        idc.set_cmt(ea, old_cmt + new_cmt, repeat)


GuidItem = namedtuple("GuidItem", "guid, bin_pattern, filepath, linenum, name_and_comment, name, comment")


def load_guid_database():
    GUID_LOADED.clear()

    idaapi.show_wait_box("HIDECANCEL\nLoading GUID database...")
    try:
        duplicate_count = 0
        invalid_count = 0
        for _type_name, type_prefix, filepath in GUID_FILES:
            with open(filepath, "r", encoding="utf8") as fp:
                lines = fp.readlines()

            line_counter = 0
            for line in lines:
                line_counter += 1

                line = line.strip()
                if not line:
                    continue

                if line[0] in ("#", ";") or (line[:2] == "//"):  # ignore comments
                    continue

                valid = False
                pos = line.find(" ")
                if pos != -1:
                    guid = line[:pos]
                    name_and_comment = line[pos + 1 :]
                    if guid and name_and_comment and (guid.count("-") == 4):
                        valid = True

                if not valid:
                    invalid_count += 1
                    print(f"{filepath}:{line_counter}: {line} - line error")
                    continue

                bin_pattern = make_binary_pattern(guid)
                if bin_pattern is None:
                    invalid_count += 1
                    print(f"{filepath}:{line_counter}: {guid} - GUID error")
                    continue

                if bin_pattern in GUID_LOADED:
                    duplicate_count += 1
                    guid_dup = GUID_LOADED[bin_pattern]
                    print(
                        f"Duplicate GUID: {guid}"
                        f"\n{guid_dup.filepath}:{guid_dup.linenum}: {guid_dup.name_and_comment}"
                        f"\n{filepath}:{line_counter}: {guid} {name_and_comment}"
                    )
                    continue

                if not name_and_comment.startswith(
                    ("GUID", "CLSID", "IID", "LIBID", "FOLDERID")
                ) and not name_and_comment.endswith(("_GUID", "_UUID")):
                    name_and_comment = type_prefix + name_and_comment

                # Extract comment
                comment = ""
                name = name_and_comment
                npos = name_and_comment.find(" ")
                if npos > 0:
                    comment = name_and_comment[npos + 1 :]
                    name = name_and_comment[:npos]

                GUID_LOADED[bin_pattern] = GuidItem(
                    guid, bin_pattern, filepath, line_counter, name_and_comment, name, comment
                )
        print(
            f"GUID read from the database: {len(GUID_LOADED)}, "
            f"duplicate: {duplicate_count}, invalid: {invalid_count}"
        )
    finally:
        idaapi.hide_wait_box()


def scan_with_guid_database():
    global SCAN_RESULT

    idaapi.show_wait_box("Scanning with GUID database...")
    try:
        for bin_pattern, guid_item in GUID_LOADED.items():
            if idaapi.user_cancelled():
                break

            ea = idaapi.cvar.inf.min_ea
            while True:
                ea = idaapi.find_binary(ea, idaapi.cvar.inf.max_ea, bin_pattern, 16, idc.SEARCH_DOWN)
                if ea == idc.BADADDR:
                    break

                SCAN_RESULT.add(ea)

                idc.del_items(ea, idc.DELIT_SIMPLE, 16)
                idc.create_struct(ea, -1, "GUID")

                if not idc.get_name(ea) or not idaapi.has_user_name(idaapi.get_full_flags(ea)):
                    # create new name
                    idc.set_name(ea, guid_item.name, idaapi.SN_FORCE)

                # Set comment
                new_cmt = f"{guid_item.name} = {{{guid_item.guid}}}"
                if guid_item.comment:
                    new_cmt = new_cmt + " //" + guid_item.comment
                set_cmt_ex(ea, new_cmt, 0)

                print(f"[*] 0x{ea:X}: {guid_item.name}")
                ea += 16

                if idaapi.user_cancelled():
                    break

        print("[*] aborted" if idaapi.user_cancelled() else "[*] finished")
        print(f"Scanning found {len(SCAN_RESULT)} GUID")
    finally:
        idaapi.hide_wait_box()


def scan_guid_in_idb():
    global SCAN_RESULT

    idaapi.show_wait_box("HIDECANCEL\nRescan GUID found in current IDA database...")
    try:
        more = set()
        heads = set(idautils.Heads()) - SCAN_RESULT
        for ea in heads:
            f = idc.get_full_flags(ea)
            if not idc.is_struct(f):
                continue
            sid = idaapi.get_strid(ea)  # get struct id, not str id
            sname = idaapi.get_struc_name(sid)
            if sname:
                sname = sname.lstrip("_")
                if sname in ("GUID", "CSLID", "IID", "UUID"):
                    print(f"0x{ea:X} {idc.get_name(ea)} '{idc.get_cmt(ea, 0)}'")
                    more.add(ea)
        print(f"[*] Found {len(more)} GUID")
    finally:
        idaapi.hide_wait_box()
        SCAN_RESULT |= more
        print(f"Total GUID found from database scan and in IDB file {len(SCAN_RESULT)}")


def main():
    idaapi.msg_clear()
    create_guid_struct()

    ret = idaapi.ASKBTN_YES
    if len(GUID_LOADED) > 0:
        ret = idaapi.ask_yn(idaapi.ASKBTN_NO, "AUTOHIDE SESSION\nReload and rescan with GUID database ?")

    if ret == idaapi.ASKBTN_CANCEL:
        return
    elif ret == idaapi.ASKBTN_YES:
        # HTC - force load COM Helper plugin and run Scan CLSIDs from registry and clsid.cfg file
        # IDA COM Helper plugin will install idb hook and auto add Interfaces + Vtbls for GUIDs found
        # with type info in the current idb's type libraries (*.til)
        print("[*] scan CLSIDs with IDA COM Helper plugin...")
        COM_Helper = "comhelper64" if idaapi.cvar.inf.is_64bit() else "comhelper"
        if not idaapi.load_and_run_plugin(COM_Helper, 1):
            # run(1) is scan CLSIDs and turn on auto
            print("[*] load and run COM Helper plugin failed")

        load_guid_database()
        scan_with_guid_database()

    ret = idaapi.ASKBTN_YES
    if len(SCAN_RESULT) > 0:
        ret = idaapi.ask_yn(idaapi.ASKBTN_YES, "AUTOHIDE SESSION\nRescan GUID found in IDA database ?")

    if ret == idaapi.ASKBTN_CANCEL:
        return
    elif ret == idaapi.ASKBTN_YES:
        scan_guid_in_idb()


if __name__ == "__main__":
    main()
