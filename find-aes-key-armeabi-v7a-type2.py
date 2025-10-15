# find-aes-key-armeabi-v7a-type2
# By GHFear @ IllusorySoftware
import idautils
import idc
import ida_bytes
import ida_search
import idaapi
import struct
import binascii
import re

SIG = "00 48 2D E9 0D ? ? ? 14 ? ? ? 00 ? ? ? D8 ? ? ? 0C ? ? ? 2C ? ? ? 00 48 BD E8"
KEY_LEN = 32 * 2
LOOK_FORWARD_INSNS = 24

def is_thumb(ea):
    try:
        t = bool(idaapi.get_sreg(ea, 'T'))
        print(f"[DEBUG] is_thumb({hex(ea)}) = {t}")
        return t
    except:
        return True

def read_u32(addr):
    b = ida_bytes.get_bytes(addr, 4)
    if not b or len(b) < 4:
        return None
    return struct.unpack('<I', b)[0]

def score_printable(buf):
    if not buf:
        return -1
    cnt = sum(1 for c in buf if 32 <= c < 127)
    return cnt

def resolve_literal_entry_addr(ldr_ea):
    print(f"[DEBUG] Resolving literal entry for LDR at {hex(ldr_ea)}")
    opval = idc.get_operand_value(ldr_ea, 1)
    if opval and opval != idc.BADADDR:
        print(f"[DEBUG] operand value = {hex(opval)}")
        if idc.get_full_flags(opval) != idc.BADADDR:
            if read_u32(opval) is not None:
                print(f"[DEBUG] Using operand value as literal entry: {hex(opval)}")
                return opval
    op_text = idc.print_operand(ldr_ea, 1) or ""
    m = re.search(r'#(-?0x[0-9A-Fa-f]+|-?\d+)', op_text)
    if m:
        try:
            imm = int(m.group(1), 0)
        except:
            imm = 0
        pc_base = ldr_ea + (4 if is_thumb(ldr_ea) else 8)
        addr = pc_base + imm
        print(f"[DEBUG] PC-relative literal entry = {hex(addr)}")
        return addr
    m2 = re.search(r'0x[0-9A-Fa-f]+', op_text)
    if m2:
        try:
            cand = int(m2.group(0), 16)
            if idc.get_full_flags(cand) != idc.BADADDR:
                print(f"[DEBUG] Parsed hex literal entry = {hex(cand)}")
                return cand
        except:
            pass
    print("[DEBUG] Could not resolve literal entry")
    return None

def compute_final_candidates(ldr_ea, add_ea):
    literal_entry = resolve_literal_entry_addr(ldr_ea)
    if not literal_entry:
        print("[DEBUG] No literal entry found")
        return []
    v = read_u32(literal_entry)
    if v is None:
        print("[DEBUG] Could not read dword at literal entry")
        return []
    pc_base = add_ea + (4 if is_thumb(add_ea) else 8)
    base = (pc_base + v) & 0xFFFFFFFF
    candidates = [base, (base + 4) & 0xFFFFFFFF, (base - 4) & 0xFFFFFFFF]
    print(f"[DEBUG] Candidate addresses: {[hex(c) for c in candidates]}")
    valid = []
    for c in candidates:
        if idc.get_full_flags(c) != idc.BADADDR:
            buf = ida_bytes.get_bytes(c, KEY_LEN)
            if buf and len(buf) >= KEY_LEN:
                valid.append((c, buf))
                print(f"[DEBUG] Valid candidate at {hex(c)}")
    return valid

def find_ldr_add_bl_after(ea):
    cur = ea
    ldr_ea = None
    add_ea = None
    bl_ea = None
    for _ in range(LOOK_FORWARD_INSNS):
        cur = idc.next_head(cur)
        if not cur or cur == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur).upper()
        if ldr_ea is None and mnem.startswith("LDR"):
            op0 = (idc.print_operand(cur,0) or "").upper()
            if op0.startswith("R0"):
                ldr_ea = cur
                print(f"[DEBUG] Found LDR at {hex(ldr_ea)}")
                continue
        if ldr_ea and add_ea is None and mnem == "ADD":
            op0 = (idc.print_operand(cur,0) or "").upper()
            op1 = (idc.print_operand(cur,1) or "").upper()
            op2 = (idc.print_operand(cur,2) or "").upper()
            if op0.startswith("R0") and ("PC" in op1 or "PC" in op2):
                add_ea = cur
                print(f"[DEBUG] Found ADD at {hex(add_ea)}")
                continue
        if add_ea and bl_ea is None and mnem in ("BL","BLX"):
            bl_ea = cur
            print(f"[DEBUG] Found BL at {hex(bl_ea)}")
            break
    return ldr_ea, add_ea, bl_ea

def dump_key(addr, buf):
    hexs = binascii.hexlify(buf).decode()
    pretty = ' '.join(hexs[i:i+2] for i in range(0, len(hexs), 2))
    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in buf)
    print("Key @ 0x{:08X}:".format(addr))
    print("Hexadecimal representation: " + pretty)
    print("AES Key: 0x" + ascii_repr)

def find_and_dump(sig):
    hits = []
    for seg in idautils.Segments():
        seg_perm = idc.get_segm_attr(seg, idc.SEGATTR_PERM)
        if not (seg_perm & idaapi.SEGPERM_EXEC):
            continue
        start = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        ea = ida_search.find_binary(start, end, sig, 16, ida_search.SEARCH_DOWN)
        while ea and ea != idc.BADADDR and ea < end:
            hits.append(ea)
            ea = ida_search.find_binary(ea + 1, end, sig, 16, ida_search.SEARCH_DOWN)

    print(f"[DEBUG] Found {len(hits)} matches for signature")

    if not hits:
        print("No matches for signature.")
        return

    found = 0
    for i, h in enumerate(hits, 1):
        print("\nMatch #{} at 0x{:08X}".format(i, h))
        ldr_ea, add_ea, bl_ea = find_ldr_add_bl_after(h)
        if not ldr_ea or not add_ea:
            print("[WARN] LDR/ADD sequence not found after match.")
            continue
        print(f"[DEBUG] LDR @ {hex(ldr_ea)}, ADD @ {hex(add_ea)}, BL @ {hex(bl_ea) if bl_ea else 'N/A'}")
        candidates = compute_final_candidates(ldr_ea, add_ea)
        if not candidates:
            print("[WARN] no valid data candidates resolved from literal pool.")
            continue
        best = None
        best_score = -1
        for addr, buf in candidates:
            score = score_printable(bytearray(buf))
            print(f"[DEBUG] Candidate {hex(addr)} score = {score}")
            if score > best_score:
                best_score = score
                best = (addr, buf)
        if not best:
            print("[WARN] no readable candidate")
            continue
        addr, buf = best
        if addr == (( (add_ea + (4 if is_thumb(add_ea) else 8)) + read_u32(resolve_literal_entry_addr(ldr_ea)) + 4) & 0xFFFFFFFF):
            print("[INFO] Chose base + 4 candidate (pipeline/assembler offset correction).")
        dump_key(addr, buf)
        found += 1
    print("\nDone — {} key(s) printed.".format(found))

if __name__ == "__main__":
    print("Using signature:", SIG)
    find_and_dump(SIG)
