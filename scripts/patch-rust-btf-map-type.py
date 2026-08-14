#!/usr/bin/env python3
"""Make the Rust BPF object libbpf-loadable: C field name `type`, one `.maps` section."""

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

    def shdr(index: int) -> int:
        return section_offset + index * section_entry_size

    def section_fields(index: int):
        return struct.unpack_from(endian + "IIQQQQIIQQ", data, shdr(index))

    names_name_off, _, _, _, names_offset, names_size, _, _, _, _ = section_fields(
        names_index
    )
    names = data[names_offset : names_offset + names_size]

    def section_name(index: int) -> bytes:
        name_offset = section_fields(index)[0]
        if name_offset >= len(names):
            fail("ELF section name offset is invalid")
        return names[name_offset:].split(b"\0", 1)[0]

    btf_index = None
    maps_indices = []
    symtab_index = None
    for index in range(section_count):
        name = section_name(index)
        if name == b".BTF":
            btf_index = index
        elif name == b".maps":
            maps_indices.append(index)
        elif name == b".symtab":
            symtab_index = index

    if btf_index is None:
        fail(".BTF section is missing or invalid")
    _, _, _, _, btf_offset, btf_size, _, _, _, _ = section_fields(btf_index)
    if btf_offset + btf_size > len(data) or btf_size < 24:
        fail(".BTF section is missing or invalid")

    magic, version, _flags, header_len, _type_off, _type_len, str_off, str_len = (
        struct.unpack_from(endian + "HBBIIIII", data, btf_offset)
    )
    if magic != 0xEB9F or version != 1 or header_len < 24:
        fail(".BTF header is invalid or unsupported")
    strings_start = btf_offset + header_len + str_off
    strings_end = strings_start + str_len
    if strings_start < btf_offset or strings_end > btf_offset + btf_size:
        fail(".BTF string table extends past the section")

    replacements = 0
    cursor = strings_start
    while True:
        cursor = data.find(b"type_\0", cursor, strings_end)
        if cursor < 0:
            break
        if cursor == strings_start or data[cursor - 1] == 0:
            data[cursor : cursor + 6] = b"type\0\0"
            replacements += 1
        cursor += 6

    patched_entries = data[strings_start:strings_end].split(b"\0")
    if b"type_" in patched_entries or b"type" not in patched_entries:
        fail("BTF map field-name verification failed after patching")

    merged = 0
    if len(maps_indices) > 1:
        if symtab_index is None:
            fail(".symtab is required to merge duplicate .maps sections")
        first = maps_indices[0]
        (
            first_name,
            first_type,
            first_flags,
            first_addr,
            first_off,
            first_size,
            first_link,
            first_info,
            first_align,
            first_entsize,
        ) = section_fields(first)
        if first_type != 1:  # SHT_PROGBITS
            fail("first .maps section is not PROGBITS")

        for extra in maps_indices[1:]:
            (
                extra_name,
                extra_type,
                extra_flags,
                extra_addr,
                extra_off,
                extra_size,
                extra_link,
                extra_info,
                extra_align,
                extra_entsize,
            ) = section_fields(extra)
            if extra_type != 1:
                fail("extra .maps section is not PROGBITS")
            if extra_off != first_off + first_size:
                fail(
                    "duplicate .maps sections are not adjacent; "
                    f"{first_off:#x}+{first_size:#x} vs {extra_off:#x}"
                )

            _, _, _, _, sym_off, sym_size, _, _, _, sym_entsize = section_fields(
                symtab_index
            )
            if sym_entsize < 24 or sym_size % 24 != 0:
                fail(".symtab entry size is invalid")
            for sym in range(0, sym_size, 24):
                st = sym_off + sym
                st_name, st_info, st_other, st_shndx, st_value, st_size = (
                    struct.unpack_from(endian + "IBBHQQ", data, st)
                )
                if st_shndx == extra:
                    struct.pack_into(
                        endian + "IBBHQQ",
                        data,
                        st,
                        st_name,
                        st_info,
                        st_other,
                        first,
                        st_value + first_size,
                        st_size,
                    )

            # Hide the leftover header. Do not name it "maps": libbpf v1+
            # treats that as a legacy map section and refuses to open.
            extra_name = 0
            first_size += extra_size
            struct.pack_into(
                endian + "IIQQQQIIQQ",
                data,
                shdr(extra),
                extra_name,
                extra_type,
                extra_flags,
                extra_addr,
                extra_off,
                extra_size,
                extra_link,
                extra_info,
                extra_align,
                extra_entsize,
            )
            merged += 1

        struct.pack_into(
            endian + "IIQQQQIIQQ",
            data,
            shdr(first),
            first_name,
            first_type,
            first_flags,
            first_addr,
            first_off,
            first_size,
            first_link,
            first_info,
            first_align,
            first_entsize,
        )

    # Re-read names after possible sh_name tweak (string table itself unchanged).
    maps_left = 0
    for index in range(section_count):
        name_offset = section_fields(index)[0]
        name = names[name_offset:].split(b"\0", 1)[0]
        if name == b".maps":
            maps_left += 1
    if maps_left != 1:
        fail(f"expected exactly one .maps section after merge, found {maps_left}")

    args.object.write_bytes(data)
    bits = []
    if replacements:
        bits.append(f"patched {replacements} BTF `type_` string(s)")
    else:
        bits.append("verified C-compatible BTF `type` field")
    if merged:
        bits.append(f"merged {merged + 1} .maps sections into one")
    print(f"{'; '.join(bits)} in {args.object}")


if __name__ == "__main__":
    main()
