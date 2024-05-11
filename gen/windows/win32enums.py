import functools
from typing import List, Optional
import re


def find_links(data: str) -> List[str]:
    regex = re.compile(r'<a href="/windows/(?:desktop|win32)/([a-zA-Z0-9/-]+)">')
    results = re.findall(regex, data)
    if not results:
        return re.findall(r'\[[a-zA-Z0-9 .-]+]\(/windows/(?:desktop|win32)/([a-zA-Z0-9/-]+)\)', data)
    return results


def first_int(possibilities: List[str]) -> Optional[int]:
    for possibility in possibilities:
        try:
            return int(possibility, 0)
        except ValueError:
            pass

    return None


def parse_win32_enum(data: str) -> Optional[dict[str, int]]:
    data = data.replace("\\", "")
    data = data.replace("*", "")
    if "constant" not in data.lower() and "value" not in data.lower():
        return None
    has_const = False
    out = {}
    for line in data.split("\n"):
        if line.startswith("## Requirements"):
            break
        if not line.startswith("|"):
            continue
        if "constant" in line.lower() or "value" in line.lower():
            has_const = True
        if has_const:
            const_name = re.findall(r"\b[A-Z_]+[0-9]?\b", line)
            if len(const_name) == 0:
                continue
            const_name = const_name[0]
            const_val = first_int(re.findall(r"\b(?:0x)?[0-9a-fA-F]+L?\b", line))
            if const_val is None:
                continue
            if "Windows Server" in line and str(const_val) in line:
                # Something like Windows Server 2008
                if line.index(str(const_val)) - line.index("Windows Server") < 20:
                    continue
            out[const_name] = const_val
    if not out:
        return None
    return out


skip = ["WinHttp/option-flags"]


@functools.lru_cache(maxsize=None)
def find_enum_in_page(link: str) -> Optional[dict[str, int]]:
    if link in skip:
        return None
    try:
        with open(f"../win32/desktop-src/{link}.md") as f:
            print(f"Parsing {link}")
            data = f.read()
            return parse_win32_enum(data)
    except (FileNotFoundError, UnicodeDecodeError):
        print(f"Failed to open {link}")
    return None
