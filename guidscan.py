# Org code: https://github.com/you0708/ida/tree/master/idapython_tools/findguid
# Lint, fix bugs and mod by HTC @VCS
# pylint: disable=C0301,C0103,C0111

import os
import binascii
import struct
import traceback

import idc
import idaapi

GUID_LIST_DIR = os.path.dirname(__file__)
GUID_LIST = []

# [name, prefix, filepath]^
GUID_LIST.append(["Class ID", "CLSID_", os.path.join(GUID_LIST_DIR, "clsids.txt")])
GUID_LIST.append(["Interface ID", "IID_", os.path.join(GUID_LIST_DIR, "iids.txt")])
GUID_LIST.append(["GUID Type", "GUID_", os.path.join(GUID_LIST_DIR, "guids.txt")])

# unclassified.txt - uncomment for testing
# GUID_LIST.append(["Unclassified GUID", "", os.path.join(GUID_LIST_DIR, "unclassified.txt")])

GUID_DICT = {}


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


def main():
    idaapi.msg_clear()
    idaapi.show_wait_box("Please wait...")

    try:
        create_guid_struct()

        # HTC - force load COM Helper plugin and run Scan CLSIDs from registry and clsid.cfg file
        # IDA COM Helper plugin will install idb hook and auto add Interfaces + Vtbls for GUIDs found
        # with type info in the current idb's type libraries (*.til)
        print("[*] scan CLSIDs with IDA COM Helper plugin...")
        COM_Helper = "comhelper64" if idaapi.cvar.inf.is_64bit() else "comhelper"
        if not idaapi.load_and_run_plugin(COM_Helper, 1):
            # run(1) is scan CLSIDs and turn on auto
            print("[*] load and run COM Helper plugin failed")

        print("[*] scan with addition GUIDs in database .txt files...")

        duplicates = 0
        for type_name, type_prefix, filepath in GUID_LIST:
            if idaapi.user_cancelled():
                break

            smsg = f"[*] scanning with file {filepath}, type {type_name}..."
            print(smsg)
            idaapi.replace_wait_box(smsg)

            with open(filepath, "r", encoding="utf8") as fp:
                lines = fp.readlines()

            line_counter = 0
            for line in lines:
                if idaapi.user_cancelled():
                    break

                line_counter += 1

                line = line.strip()
                if not line:
                    continue

                if line[0] in ("#", ";") or (line[:2] == "//"):  # ignore comments
                    continue

                valid = False
                pos = line.find(" ")
                if pos != -1:
                    guid = line[:pos].upper()
                    guid_name = line[pos + 1 :]
                    if guid and guid_name and guid.count("-") == 4:
                        valid = True

                if not valid:
                    print(f"{filepath}:{line_counter}: {line} - data error")
                    continue

                binary_pattern = make_binary_pattern(guid)
                if binary_pattern is None:
                    print(f"{filepath}:{line_counter}: {line} - data error")
                    continue

                if binary_pattern not in GUID_DICT:
                    GUID_DICT[binary_pattern] = [filepath, line_counter, guid_name]
                else:
                    duplicates += 1
                    print(
                        f"Duplicate GUID: {guid}"
                        f"\n{GUID_DICT[binary_pattern][0]}:{GUID_DICT[binary_pattern][1]}: {guid} {GUID_DICT[binary_pattern][2]}"
                        f"\n{filepath}:{line_counter}: {guid} {guid_name}"
                    )

                if not guid_name.startswith(("GUID", "CLSID", "IID", "LIBID", "FOLDERID")) and not guid_name.endswith(
                    ("_GUID", "_UUID")
                ):
                    guid_name = type_prefix + guid_name

                ea = idaapi.cvar.inf.min_ea
                while True:
                    ea = idaapi.find_binary(ea, idaapi.cvar.inf.max_ea, binary_pattern, 16, idc.SEARCH_DOWN)
                    if ea == idc.BADADDR:
                        break

                    idc.del_items(ea, idc.DELIT_SIMPLE, 16)
                    idc.create_struct(ea, -1, "GUID")
                    if not idc.get_name(ea) or not idaapi.has_user_name(idaapi.get_full_flags(ea)):
                        # create new name
                        idc.set_name(ea, guid_name, idaapi.SN_FORCE)
                    idc.set_cmt(ea, f"{guid_name} = {{{guid}}}", 0)

                    print(f"[*] 0x{ea:X}: {guid_name}")
                    ea += 16

                    if idaapi.user_cancelled():
                        break

        print("[*] aborted" if idaapi.user_cancelled() else "[*] finished")

        if duplicates > 0:
            print(f"Found {duplicates} GUID duplicate in database")

    except:
        traceback.print_exc()

    finally:
        idaapi.hide_wait_box()


if __name__ == "__main__":
    main()
