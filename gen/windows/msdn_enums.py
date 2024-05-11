import re
import string
import json
import hashlib

hash_ = lambda x: str(int.from_bytes(hashlib.md5(x.encode()).digest(), byteorder='big'))[:5]

enum_regex = re.compile(r"<dt><b>\s*([A-Z_2-3]+[0-9]*|[0-9]+)\s*</b></dt>\n<dt>\s*((?:0x)?[0-9a-fA-F]+)L?(?: \(.+\))?\s*</dt>")

enums = json.loads(open("./generated/enums.json").read())


def parse_enum(data: str) -> dict[str, int]:
    out = {}
    matches = re.findall(enum_regex, data)
    for k, v in matches:
        out[k] = int(v, 0)
    return out


def enum_hash(enum: dict[str, int]) -> str:
    return hash_(str(sorted(enum.items())))


def enum_id(enum: dict[str, int]) -> str:
    longest_prefix = ""
    while True:
        cur = None
        cur_len = len(longest_prefix)
        for k in enum.keys():
            if k == "0":
                continue
            if len(k) <= cur_len:
                cur = None
                break
            if cur is None:
                cur = k[cur_len]
            else:
                if cur != k[cur_len]:
                    cur = None
                    break
        if cur is None:
            break
        longest_prefix += cur
    if len(longest_prefix) == 0 or longest_prefix[-1] != "_":
        return enum_hash(enum)

    prefix = longest_prefix[:-1]
    enum_name = prefix
    count = 1
    cur_hash = enum_hash(compress_enum(enum, enum_name))
    while enum_name in enums:
        if cur_hash == enum_hash(enums[enum_name]):
            return enum_name
        else:
            enum_name = f"{prefix}_{count}"
            count += 1
    return enum_name


def all_digits(val: str):
    return all(x in string.digits for x in val)


def compress_enum(enum: dict[str, int], enum_id: str) -> dict[str, int]:
    if all_digits(enum_id):
        return enum

    out = {}

    if "_" in enum_id and all_digits(enum_id.rsplit("_", 1)[1]):
        enum_id = enum_id.rsplit("_", 1)[0]

    for k, v in enum.items():
        if k == "0":
            out[k] = v
            continue
        out[k[len(enum_id) + 1:]] = v

    return out


def expand_enum(enum: dict[str, int], enum_id: str) -> dict[str, int]:
    if not all_digits(enum_id):
        for k, v in enum.items():
            del enum[k]
            if k == "0":
                enum["NULL"] = v
            else:
                enum[f"{enum_id}_{k}"] = v
        return enum

    for k, v in enum.items():
        if k == "0":
            del enum[k]
            enum["NULL"] = v
    return enum
