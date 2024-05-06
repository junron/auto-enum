import os
import json

def resolve(func):
    data = ""
    for arg, argvalue in func["args"].items():
        for v in argvalue:
            body = "#include <stdio.h>\nint main(){\n"
            body += f'printf("{arg}___{v}=%d\\n", {v});\n'
            body += "}"
            open("./resolve.c", "w").write(func["prefix"] + body)
            os.system("rm -f resolve")
            os.system("gcc resolve.c -o resolve")
            _data = os.popen("./resolve").read()
            if len(_data.strip()):
                data += _data
            else:
                print(arg, "Could not resolve:", argvalue)
                exit(1)
    out = {}
    for line in data.splitlines():
        k, v = line.split("=")
        v = int(v)
        arg, enumname = k.split("___")
        if arg in out:
            out[arg][enumname] = v
        else:
            out[arg] = {enumname: v}
    os.system("rm -f resolve.c resolve")
    return out


def resolve_enums(enums):
    if not os.path.exists("cache.json"):
        open("./cache.json","w").write("{}")
        full_resolved = {}
    else:
        full_resolved = json.load(open("./cache.json"))
    for funcname in enums.keys():
        if funcname not in full_resolved or list(enums[funcname]["args"].keys()) != list(full_resolved[funcname].keys()):
            print("Resolving enum values for", funcname)
            full_resolved[funcname] = resolve(enums[funcname])
            json.dump(full_resolved, open("./cache.json", "w"))
    return full_resolved
