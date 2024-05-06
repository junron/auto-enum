import argparse
import json
import os


def diff_keys(a_key, b_key):
    for k in a_key:
        if k not in b_key:
            print("[X]", k, "not in b")
            return True
    for k in b_key:
        if k not in a_key:
            print("[X]", k, "not in a")
            return True
    return False
def diff_json(ja, jb):
    if ja == jb:
        print("[+]", "Objects are identical")
        return False
    a_key = list(ja.keys())
    b_key = list(jb.keys())
    if diff_keys(a_key, b_key):
        return True
    for k in a_key:
        if ja[k] != jb[k]:
            print("[X]", f"a[{k}] != b[{k}]")
            return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("a")
    parser.add_argument("b")

    args = parser.parse_args()
    a = args.a
    b = args.b
    has_diff = False
    print("Diffing enums.json")
    a_enum = json.load(open(f"{a}/enums.json"))
    b_enum = json.load(open(f"{b}/enums.json"))
    if diff_json(a_enum, b_enum):
        exit(1)
    a_funcs = os.listdir(f"{a}/functions")
    b_funcs = os.listdir(f"{b}/functions")
    print("Comparing functions")
    if diff_keys(a_funcs, b_funcs):
        exit(1)
    for func in a_funcs:
        print("Diffing", func)
        a_func = json.load(open(f"{a}/functions/{func}"))
        b_func = json.load(open(f"{b}/functions/{func}"))
        if diff_json(a_func, b_func):
            exit(1)