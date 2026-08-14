#!/usr/bin/env python3
"""Give Rust libbpf map definitions the C-compatible BTF field name `type`."""

import argparse
import struct
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("object", type=Path)
    args = parser.parse_args()

    data = bytearray(args.object.read_bytes())
    if data[:4] != b"\x7fELF" or len(data) < 64:
        fail(f"{args.object} is not an ELF object")
    if data[4] != 2:
        fail("only ELF64 objects are supported")
    if data[5] == 1:
        endian = "<"
    elif data[5] == 2:
        endian = ">"
    else:
        fail("ELF object has an invalid byte order")

    elf_header = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data)
    section_offset = elf_header[6]
    section_entry_size = elf_header[11]
    section_count = elf_header[12]
    names_index = elf_header[13]
    if section_entry_size < 64 or not (0 < names_index < section_count):
        fail("ELF section table is invalid or unsupported")
    if section_offset + section_entry_size * section_count > len(data):
        fail("ELF section table extends past the end of the file")

    def section(index: int) -> tuple[int, int, int]:
        offset = section_offset + index * section_entry_size
        fields = struct.unpack_from(endian + "IIQQQQIIQQ", data, offset)
        return fields[0], fields[4], fields[5]

    _, names_offset, names_size = section(names_index)
    names = data[names_offset : names_offset + names_size]
    btf_offset = btf_size = None
    for index in range(section_count):
        name_offset, candidate_offset, candidate_size = section(index)
        if name_offset >= len(names):
            fail("ELF section name offset is invalid")
        name = names[name_offset :].split(b"\0", 1)[0]
        if name == b".BTF":
            btf_offset, btf_size = candidate_offset, candidate_size
            break
    if btf_offset is None or btf_offset + btf_size > len(data):
        fail(".BTF section is missing or invalid")
    if btf_size < 24:
        fail(".BTF section is too short")

    magic, version, _flags, header_len, _type_off, _type_len, str_off, str_len = (
        struct.unpack_from(endian + "HBBIIIII", data, btf_offset)
    )
    if magic != 0xEB9F or version != 1 or header_len < 24:
        fail(".BTF header is invalid or unsupported")
    strings_start = btf_offset + header_len + str_off
    strings_end = strings_start + str_len
    if strings_start < btf_offset or strings_end > btf_offset + btf_size:
        fail(".BTF string table extends past the section")

    strings = data[strings_start:strings_end]
    entries = strings.split(b"\0")
    replacements = sum(entry == b"type_" for entry in entries)
    cursor = strings_start
    while True:
        cursor = data.find(b"type_\0", cursor, strings_end)
        if cursor < 0:
            break
        if cursor == strings_start or data[cursor - 1] == 0:
            data[cursor : cursor + 6] = b"type\0\0"
        cursor += 6

    patched_entries = data[strings_start:strings_end].split(b"\0")
    if b"type_" in patched_entries or b"type" not in patched_entries:
        fail("BTF map field-name verification failed after patching")
    args.object.write_bytes(data)
    if replacements:
        print(f"patched {replacements} BTF `type_` string(s) in {args.object}")
    else:
        print(f"verified C-compatible BTF `type` field in {args.object}")


if __name__ == "__main__":
    main()
