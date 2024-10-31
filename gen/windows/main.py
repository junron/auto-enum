import json
import os
import re
import string

import yaml


def remove_aw(name: str) -> str:
    for letter in "AW":
        if name.endswith(letter):
            return name[:-1]
    return name


def remove_ansicode(description: str) -> str:
    for x in [" (ANSI)", " (UNICODE)"]:
        if description.endswith(x):
            return description.replace(x, "")
    return description


def split_markdown_sections(data: str, level: int, add_newline=False) -> dict[str, str]:
    if add_newline:
        data = "\n" + data
    sections = data.split(f"\n{'#' * level} -")
    out = {}
    for section in sections:
        if '#' * level in section and not add_newline:
            return split_markdown_sections(data, level, True)
    sections.pop(0)
    for section in sections:
        parts = section.split("\n", maxsplit=1)
        if len(parts) != 2:
            parts.append("")
        name, rest = parts
        out[name] = rest.strip()
    return out


def parse_basic_data(data: str):
    parts = data.split('---')
    try:
        basic_data = yaml.safe_load(parts[1])
    except Exception as e:
        print("YAML parse failed!", parts[1], e)
        return None
    func_name = set([remove_aw(name) for name in basic_data["api_name"]]).pop()
    if " " in func_name:
        func_name = remove_aw(func_name.split(" ")[0])
    if "description" not in basic_data:
        return None
    if basic_data["description"] is None or "callback function" in basic_data["description"].lower():
        return None
    return {
        "name": func_name,
    }


bad_param_name_start = ["p", "h", "pv", "cch", "psz", "b", "lpsz", "lp"]


def parse_body(data: str):
    parts = data.split('---')
    body = split_markdown_sections(parts[2], 2)
    if "parameters" not in body:
        print("Params not found")
        return None
    params = split_markdown_sections(body["parameters"], 3)
    args = []
    has_enum = False
    varargs = False
    for k, v in params.items():
        parts = k.split(" ", maxsplit=2)
        if len(parts) != 3:
            if len(parts) == 2 and parts[1] == "...":
                varargs = True
                break
            print("Failed to parse params!")
            return None
        _, param_name, mode = parts
        is_in_param = "in" in mode and ("out" not in mode and "ref" not in mode)
        param_name_likely_not_enum = any(re.match(f"{x}[A-Z]", param_name) for x in bad_param_name_start) 
        is_handle = "hwnd" in param_name or "handle" in param_name.lower()
        if not is_in_param or param_name_likely_not_enum or is_handle:
            args.append({
                "name": param_name,
                # TODO: Determine type of param
                "type": ""
            })
            continue
        enums = msdn_enums.parse_enum(v)
        if enums:
            enum_id = msdn_enums.enum_id(enums)
            msdn_enums.enums[enum_id] = msdn_enums.compress_enum(enums, enum_id)
            args.append({
                "name": param_name,
                "enum": enum_id
            })
            has_enum = True
        elif not v.startswith("A pointer to"):
            resultant_enum = {}
            links = win32enums.find_links(v)
            for link in links:
                enum = win32enums.find_enum_in_page(link)
                if enum is not None:
                    resultant_enum |= enum
            if resultant_enum:
                enum_id = msdn_enums.enum_id(resultant_enum)
                msdn_enums.enums[enum_id] = msdn_enums.compress_enum(resultant_enum, enum_id)
                args.append({
                    "name": param_name,
                    "enum": enum_id
                })
                has_enum = True
                print("Deep enum search success: ", enum_id)
    return {
        "args": args,
        "has_enum": has_enum,
        "varargs": varargs
    }


if __name__ == '__main__':
    if not os.path.isdir("generated"):
        os.mkdir("generated")
        open("./generated/enums.json", "w").write("{}")
    if not os.path.isdir("generated/functions"):
        os.mkdir("generated/functions")
    import msdn_enums
    import win32enums
    indent = 2
    testcases = []
    whitelist = [
        "winsock2",
        "processthreadsapi",
        "fileapi",
        "memoryapi",
        "winuser",
        "http",
        "ws2tcpip",
        "wininet",
        "winhttp",
        "winsvc",
        "bcrypt",
        "wincrypt",
        "winbase"
    ]
    for x in whitelist:
        if not os.path.isdir(f"../sdk-api/sdk-api-src/content/{x}"):
            continue
        for file in os.listdir(f"../sdk-api/sdk-api-src/content/{x}"):
            if file.endswith(".md"):
                file = file[:-3]
            if file == "index":
                continue
            testcases.append(f"{x}/{file}")
    count = 0
    for testcase in testcases:
        count += 1
        if count % 100 == 0:
            json.dump(msdn_enums.enums, open("./generated/enums.json", "w"), indent=indent)
        print("TC", testcase)
        try:
            data = open(f"../sdk-api/sdk-api-src/content/{testcase}.md", "r").read()
        except:
            print("Failed to read!")
            continue
        result = parse_basic_data(data)
        if result is None:
            continue
        if any(x not in string.ascii_letters + string.digits for x in result["name"]):
            print("Bad name", result["name"])
            continue
        body = parse_body(data)
        if body is None:
            continue
        result |= body
        if not body["has_enum"]:
            print("No enums")
            if os.path.exists(f"./generated/functions/{result['name']}.json"):
                os.unlink(f"./generated/functions/{result['name']}.json")
            continue
        del result["has_enum"]
        json.dump(result, open(f"./generated/functions/{result['name']}.json", "w"), indent=indent)
    json.dump(msdn_enums.enums, open("./generated/enums.json", "w"), indent=indent)
