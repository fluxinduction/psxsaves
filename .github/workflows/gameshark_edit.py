#!/usr/bin/env python3
"""
GameShark V5 VM1 Cheat Editor
-----------------------------
A conservative editor for 128 KiB PlayStation memory-card images containing
the GameShark V5 save structure examined during reverse engineering.

It:
  * Finds the GameShark payload by validating the wrapper CRC.
  * Reads the 32-byte object records.
  * Adds cheat-name records and one or more 6-byte GameShark code entries.
  * Preserves the opaque 8-byte record suffix (padding + 6-byte trailer)
    by cloning it from an existing code record.
  * Updates the object count, object-array size, payload length and wrapper CRC.
  * Writes to a NEW output image; the input is never modified.

Input code syntax:
    800FE10D 4444
    800FE10D4444

One cheat may contain multiple code lines. The editor appends each new cheat
as a name record followed by its code records.

Important:
This implementation is based on the observed GameShark V5 record format and
the sample card image discussed during reverse engineering. It refuses to
edit files that do not match the expected structure or fit in the existing
8 KiB memory-card block. It does not expand the memory-card allocation chain.
"""

from __future__ import annotations

import os
import re
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

CARD_SIZE = 128 * 1024
BLOCK_SIZE = 8192
BLOCK_DATA_OFFSET = 0x200
WRAPPER_SIZE = 8

# Payload layout
CONFIG_SIZE = 0x24
ARRAY_HEADER_SIZE = 8
RECORD_SIZE = 0x20
FOOTER_SIZE = 8

# Observed record types / values
FLAG_GAME_NAME = 0x80400000
FLAG_CHEAT_NAME = 0x40400000
FLAG_CODE = 0x20400000
RECORD_ID = 0x45

# CRC-16/CCITT table algorithm used by the GameShark wrapper:
# poly 0x1021, init 0xFFFF, final XOR 0x425E.
CRC_FINAL_XOR = 0x425E


@dataclass
class Cheat:
    name: str
    codes: List[bytes]


@dataclass
class LocatedSave:
    wrapper_offset: int
    payload_offset: int
    payload_length: int
    block_start: int
    block_number: int
    object_count: int
    array_size: int
    records_offset: int
    records_end: int
    code_suffix: bytes


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc ^ CRC_FINAL_XOR


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def put_u32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def parse_code(line: str) -> bytes:
    """Convert 12 hex digits (address + 16-bit value) to the 6-byte code."""
    compact = re.sub(r"[\s:_-]", "", line).upper()
    if compact.startswith("0X"):
        compact = compact[2:]
    if not re.fullmatch(r"[0-9A-F]{12}", compact):
        raise ValueError(
            f"Invalid code {line!r}. Expected 12 hex digits, e.g. "
            "'800FE10D 4444'."
        )
    return bytes.fromhex(compact)


def parse_code_text(text: str) -> List[bytes]:
    codes: List[bytes] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        # Permit comma/semicolon-separated codes on a single line.
        for part in re.split(r"[,;]", line):
            part = part.strip()
            if part:
                try:
                    codes.append(parse_code(part))
                except ValueError as exc:
                    raise ValueError(f"Line {line_no}: {exc}") from exc
    if not codes:
        raise ValueError("Enter at least one GameShark code.")
    return codes


def decode_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace").strip()


def find_save(card: bytes) -> LocatedSave:
    if len(card) != CARD_SIZE:
        raise ValueError(
            f"Expected a 128 KiB memory-card image; file is {len(card):,} bytes."
        )

    candidates = []
    # In the sample card, the GameShark wrapper starts 0x200 bytes into
    # an 8 KiB data block. Scan all 15 user-data blocks.
    for block_number in range(1, 16):
        block_start = block_number * BLOCK_SIZE
        wrapper = block_start + BLOCK_DATA_OFFSET
        if wrapper + WRAPPER_SIZE > len(card):
            continue

        payload_len = u32(card, wrapper)
        stored_crc = struct.unpack_from("<H", card, wrapper + 4)[0]
        payload = card[wrapper + WRAPPER_SIZE:wrapper + WRAPPER_SIZE + payload_len]

        if payload_len < CONFIG_SIZE + ARRAY_HEADER_SIZE + FOOTER_SIZE:
            continue
        if wrapper + WRAPPER_SIZE + payload_len > block_start + BLOCK_SIZE:
            continue
        if crc16_ccitt(payload) != stored_crc:
            continue

        # Validate the observed internal object-array structure.
        count = u32(payload, CONFIG_SIZE)
        array_size = u32(payload, CONFIG_SIZE + 4)
        expected_size = ARRAY_HEADER_SIZE + count * RECORD_SIZE
        if array_size != expected_size:
            continue
        if CONFIG_SIZE + array_size + FOOTER_SIZE != payload_len:
            continue

        records_offset = WRAPPER_SIZE + CONFIG_SIZE + ARRAY_HEADER_SIZE
        records_end = records_offset + count * RECORD_SIZE
        if records_end > WRAPPER_SIZE + payload_len - FOOTER_SIZE:
            continue

        # Require at least one known code record and a sequential descriptor
        # pointer field before treating this as the target save.
        code_suffix = None
        for i in range(count):
            off = records_offset + i * RECORD_SIZE
            flags = u32(payload, CONFIG_SIZE + ARRAY_HEADER_SIZE + i * RECORD_SIZE + 4)
            if flags == FLAG_CODE:
                code_suffix = payload[
                    CONFIG_SIZE + ARRAY_HEADER_SIZE + i * RECORD_SIZE + 8:
                    CONFIG_SIZE + ARRAY_HEADER_SIZE + i * RECORD_SIZE + 16
                ]
                break
        if code_suffix is None:
            continue

        candidates.append(
            LocatedSave(
                wrapper_offset=wrapper,
                payload_offset=wrapper + WRAPPER_SIZE,
                payload_length=payload_len,
                block_start=block_start,
                block_number=block_number,
                object_count=count,
                array_size=array_size,
                records_offset=records_offset,
                records_end=records_end,
                code_suffix=code_suffix,
            )
        )

    if len(candidates) == 0:
        raise ValueError(
            "No valid GameShark V5 save was found. The file must be a 128 KiB "
            "PS1 memory-card image containing the expected GameShark wrapper."
        )
    if len(candidates) > 1:
        details = ", ".join(f"block {c.block_number}" for c in candidates)
        raise ValueError(
            "More than one matching GameShark payload was found "
            f"({details}). This editor will not guess which one to modify."
        )
    return candidates[0]


def read_cheat_groups(card: bytes, save: LocatedSave) -> List[Tuple[str, int]]:
    payload = card[
        save.payload_offset:save.payload_offset + save.payload_length
    ]
    groups: List[Tuple[str, int]] = []
    current_name: Optional[str] = None
    current_count = 0

    for i in range(save.object_count):
        off = CONFIG_SIZE + ARRAY_HEADER_SIZE + i * RECORD_SIZE
        flags = u32(payload, off + 4)
        data = payload[off + 16:off + 32]

        if flags in (FLAG_GAME_NAME, FLAG_CHEAT_NAME):
            if current_name is not None:
                groups.append((current_name, current_count))
            current_name = decode_name(data)
            current_count = 0
        elif flags == FLAG_CODE and current_name is not None:
            current_count += 1

    if current_name is not None:
        groups.append((current_name, current_count))
    return groups


def append_cheats(card: bytes, save: LocatedSave, cheats: List[Cheat]) -> bytes:
    if not cheats:
        raise ValueError("There are no new cheats to add.")

    additions: List[bytes] = []
    next_ptr = None
    payload = card[
        save.payload_offset:save.payload_offset + save.payload_length
    ]

    # The record's +0x0C field is a runtime descriptor pointer. Existing
    # records in the inspected save use a 0x10-byte stride.
    if save.object_count:
        last_off = CONFIG_SIZE + ARRAY_HEADER_SIZE + (save.object_count - 1) * RECORD_SIZE
        next_ptr = (u32(payload, last_off + 12) + 0x10) & 0xFFFFFFFF
    if next_ptr is None:
        raise ValueError("Could not determine the next record descriptor pointer.")

    for cheat in cheats:
        name_bytes = cheat.name.encode("ascii", errors="strict")
        if not name_bytes or len(name_bytes) > 15:
            raise ValueError(
                f"Cheat name {cheat.name!r} must be 1–15 ASCII characters."
            )
        if not cheat.codes:
            raise ValueError(f"Cheat {cheat.name!r} has no codes.")

        # Name object: 32-byte record, 16-byte data area containing a
        # NUL-terminated ASCII label.
        name_record = bytearray(RECORD_SIZE)
        put_u32(name_record, 0, RECORD_SIZE)
        put_u32(name_record, 4, FLAG_CHEAT_NAME)
        put_u32(name_record, 8, RECORD_ID)
        put_u32(name_record, 12, next_ptr)
        name_record[16:16 + len(name_bytes)] = name_bytes
        additions.append(bytes(name_record))
        next_ptr = (next_ptr + 0x10) & 0xFFFFFFFF

        for code in cheat.codes:
            code_record = bytearray(RECORD_SIZE)
            put_u32(code_record, 0, RECORD_SIZE)
            put_u32(code_record, 4, FLAG_CODE)
            put_u32(code_record, 8, RECORD_ID)
            put_u32(code_record, 12, next_ptr)
            # 6-byte GameShark code + 2-byte zero pad + cloned opaque suffix.
            code_record[16:22] = code
            code_record[22:24] = b"\x00\x00"
            code_record[24:32] = save.code_suffix
            additions.append(bytes(code_record))
            next_ptr = (next_ptr + 0x10) & 0xFFFFFFFF

    added_bytes = b"".join(additions)
    new_count = save.object_count + len(additions)
    new_array_size = ARRAY_HEADER_SIZE + new_count * RECORD_SIZE
    new_payload_len = save.payload_length + len(added_bytes)

    # The save file occupies one 8 KiB PS1 memory-card block. Do not attempt
    # to allocate another block or rewrite the card directory/FAT.
    block_end = save.block_start + BLOCK_SIZE
    new_payload_end = save.payload_offset + new_payload_len
    if new_payload_end > block_end:
        remaining = block_end - (save.payload_offset + save.payload_length)
        raise ValueError(
            f"Not enough free room in the existing memory-card block. "
            f"This addition needs {len(added_bytes)} bytes; only {remaining} "
            "bytes remain. The program will not resize the card allocation."
        )

    new_payload = bytearray(payload)
    insert_at = CONFIG_SIZE + ARRAY_HEADER_SIZE + save.object_count * RECORD_SIZE
    footer = bytes(new_payload[-FOOTER_SIZE:])
    new_payload = (
        new_payload[:insert_at]
        + bytearray(added_bytes)
        + new_payload[insert_at:-FOOTER_SIZE]
        + bytearray(footer)
    )

    put_u32(new_payload, CONFIG_SIZE, new_count)
    put_u32(new_payload, CONFIG_SIZE + 4, new_array_size)

    if len(new_payload) != new_payload_len:
        raise AssertionError("Internal length calculation mismatch.")

    out = bytearray(card)
    out[save.payload_offset:save.payload_offset + new_payload_len] = new_payload

    wrapper = save.wrapper_offset
    put_u32(out, wrapper, new_payload_len)
    struct.pack_into("<H", out, wrapper + 4, crc16_ccitt(bytes(new_payload)))

    # Re-validate the just-written wrapper CRC and internal object counts.
    check_len = u32(out, wrapper)
    check_crc = struct.unpack_from("<H", out, wrapper + 4)[0]
    check_payload = bytes(out[wrapper + WRAPPER_SIZE:wrapper + WRAPPER_SIZE + check_len])
    if crc16_ccitt(check_payload) != check_crc:
        raise AssertionError("CRC verification failed after writing.")
    if u32(check_payload, CONFIG_SIZE) != new_count:
        raise AssertionError("Object-count verification failed.")

    return bytes(out)


class AddCheatDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self.title("Add cheat")
        self.resizable(True, True)
        self.result: Optional[Cheat] = None
        self.transient(master)
        self.grab_set()

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Cheat name (1–15 ASCII characters):").pack(anchor="w")
        self.name_var = tk.StringVar()
        name_entry = ttk.Entry(body, textvariable=self.name_var, width=36)
        name_entry.pack(fill="x", pady=(3, 10))
        name_entry.focus_set()

        ttk.Label(
            body,
            text="GameShark codes (one per line; format: 800FE10D 4444):"
        ).pack(anchor="w")
        self.codes_text = tk.Text(body, width=42, height=8, wrap="none")
        self.codes_text.pack(fill="both", expand=True, pady=(3, 10))
        self.codes_text.insert("1.0", "800FE10D 4444\n")

        buttons = ttk.Frame(body)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Add cheat", command=self.accept).pack(
            side="right", padx=(0, 8)
        )

        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Control-Return>", lambda _e: self.accept())

    def accept(self) -> None:
        name = self.name_var.get().strip()
        try:
            if not name:
                raise ValueError("Enter a cheat name.")
            name.encode("ascii", errors="strict")
            if len(name.encode("ascii")) > 15:
                raise ValueError("The cheat name must be no longer than 15 ASCII bytes.")
            codes = parse_code_text(self.codes_text.get("1.0", "end"))
        except (ValueError, UnicodeEncodeError) as exc:
            messagebox.showerror("Invalid cheat", str(exc), parent=self)
            return
        self.result = Cheat(name, codes)
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GameShark V5 VM1 Cheat Editor")
        self.geometry("760x560")
        self.minsize(680, 480)

        self.card: Optional[bytes] = None
        self.save: Optional[LocatedSave] = None
        self.cheats_to_add: List[Cheat] = []
        self.source_path: Optional[str] = None

        self._build_ui()

    def _build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        top = ttk.Frame(root)
        top.pack(fill="x")
        ttk.Button(top, text="Open memory-card image…", command=self.open_card).pack(side="left")
        ttk.Button(top, text="Add cheat…", command=self.add_cheat, state="disabled").pack(
            side="left", padx=8
        )
        self.add_button = top.winfo_children()[-1]
        self.save_button = ttk.Button(
            top, text="Save edited copy…", command=self.save_copy, state="disabled"
        )
        self.save_button.pack(side="left")

        self.file_label = ttk.Label(root, text="No memory-card image loaded.", foreground="#555")
        self.file_label.pack(anchor="w", pady=(10, 4))

        self.status_label = ttk.Label(root, text="Open a 128 KiB PS1 memory-card image.")
        self.status_label.pack(anchor="w", pady=(0, 8))

        columns = ("name", "codes")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=13)
        self.tree.heading("name", text="Existing cheat / group name")
        self.tree.heading("codes", text="Code records")
        self.tree.column("name", width=500, anchor="w")
        self.tree.column("codes", width=110, anchor="center")
        self.tree.pack(fill="both", expand=True)

        pending_frame = ttk.LabelFrame(root, text="Cheats queued to add", padding=8)
        pending_frame.pack(fill="x", pady=(10, 0))
        self.pending_list = tk.Listbox(pending_frame, height=4)
        self.pending_list.pack(side="left", fill="both", expand=True)
        ttk.Button(
            pending_frame, text="Remove selected", command=self.remove_pending
        ).pack(side="left", padx=(8, 0))

        note = (
            "Safety: edits are written to a new file. Existing records are preserved. "
            "New code records copy the opaque trailer from an existing code record."
        )
        ttk.Label(root, text=note, wraplength=700, foreground="#555").pack(
            anchor="w", pady=(10, 0)
        )

    def open_card(self):
        path = filedialog.askopenfilename(
            title="Open PS1 memory-card image",
            filetypes=[
                ("PS1 memory-card images", "*.mcd *.mcr *.vm1 *.VM1"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            data = Path(path).read_bytes()
            save = find_save(data)
            groups = read_cheat_groups(data, save)
        except Exception as exc:
            messagebox.showerror("Could not open image", str(exc))
            return

        self.card = data
        self.save = save
        self.source_path = path
        self.cheats_to_add.clear()
        self.pending_list.delete(0, "end")
        for item in self.tree.get_children():
            self.tree.delete(item)
        for name, count in groups:
            self.tree.insert("", "end", values=(name or "(unnamed)", count))

        self.file_label.config(text=f"Loaded: {path}")
        self.status_label.config(
            text=(
                f"Found GameShark payload in memory-card block {save.block_number}; "
                f"{save.object_count} records, payload {save.payload_length:#x} bytes. "
                "New cheats can be queued."
            )
        )
        self.add_button.config(state="normal")
        self.save_button.config(state="normal")

    def add_cheat(self):
        if self.save is None:
            return
        dialog = AddCheatDialog(self)
        self.wait_window(dialog)
        if dialog.result is not None:
            self.cheats_to_add.append(dialog.result)
            self.pending_list.insert(
                "end", f"{dialog.result.name} — {len(dialog.result.codes)} code(s)"
            )

    def remove_pending(self):
        selection = self.pending_list.curselection()
        if not selection:
            return
        idx = selection[0]
        self.pending_list.delete(idx)
        del self.cheats_to_add[idx]

    def save_copy(self):
        if self.card is None or self.save is None or self.source_path is None:
            return
        if not self.cheats_to_add:
            messagebox.showinfo("Nothing to save", "Add at least one cheat first.")
            return

        default_name = Path(self.source_path).stem + "_edited" + Path(self.source_path).suffix
        path = filedialog.asksaveasfilename(
            title="Save edited memory-card image",
            initialfile=default_name,
            defaultextension=Path(self.source_path).suffix or ".mcd",
            filetypes=[
                ("PS1 memory-card images", "*.mcd *.mcr *.vm1"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            edited = append_cheats(self.card, self.save, self.cheats_to_add)
            Path(path).write_bytes(edited)
            # Re-open the written image and confirm it is structurally valid.
            verified = find_save(Path(path).read_bytes())
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return

        messagebox.showinfo(
            "Saved",
            f"Edited copy saved to:\n{path}\n\n"
            f"New record count: {verified.object_count}\n"
            f"New payload size: {verified.payload_length:#x} bytes\n"
            "The original image was not changed.",
        )
        self.status_label.config(
            text=f"Saved edited copy: {verified.object_count} records, "
                 f"{verified.payload_length:#x}-byte payload."
        )


if __name__ == "__main__":
    App().mainloop()
