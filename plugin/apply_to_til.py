import ida
import idaapi
import os

from auto_enum import get_function_map, get_or_add_enum


def type_for_name(til:idaapi.til_t, s:str)->idaapi.tinfo_t:
    named_type = idaapi.get_named_type(til, s, 0)
    if named_type is None:
        return None
    (code, type_str, fields_str, cmt, field_cmts, sclass, value) = named_type
    #print(f"{code=}, {type_str=}, {fields_str=}, {cmt=}, {field_cmts=}, {sclass=}, {value=}")
    t = idaapi.tinfo_t()
    # deserialize(self, til, ptype, pfields=None, pfldcmts=None, cmt=None) -> bool
    assert t.deserialize(til, type_str, fields_str)#, field_cmts, cmt)
    return t


def change_type(til:idaapi.til_t, name:str, ida_name:str, BOOL)->bool:
    ti = type_for_name(til, ida_name)

    if not ti:
        return

    funcdata = idaapi.func_type_data_t()
    ok = ti.get_func_details(funcdata)
    assert ok, "Failed to get function details"

    if not funcdata:
            return
    
    
    changed = False

    for arg in funcdata:
        if arg.type.is_ptr():
            continue
        type_name = arg.type.get_type_name()
        if type_name is not None and type_name.lower() in ["bool"]:
            arg.type = BOOL
            changed = True
        elif arg.type.is_integral() and not arg.type.is_enum():
            func = func_map[name]
            matching_arg = next((a for a in func.arguments if a.name == arg.name), None)
            if matching_arg and matching_arg.enum is not None:
                enum_name = get_or_add_enum(func_map, matching_arg.enum, til)
                enum_type = idaapi.tinfo_t()
                enum_type.get_named_type(til, enum_name)
                arg.type = enum_type
                changed = True
        
    if changed:
        ti = idaapi.tinfo_t()
        ti.create_func(funcdata)
    
        err = ti.set_symbol_type(til, ida_name, idaapi.NTF_REPLACE | idaapi.NTF_COPY)

        if err:
            err_str = idaapi.tinfo_errstr(err)
            print(f"Error setting symbol type for {name}: {err_str}")

idadir =  "/Applications/IDA Professional 9.0.app/Contents/MacOS/til/pc/"

tils = os.listdir(idadir)

for til_name in tils:
    if "mssdk" not in til_name:
        continue

    ida.open_database(r"a.i64", False)

    til = idaapi.load_til("pc/" + til_name)
    func_map = get_function_map("windows")

    BOOL = idaapi.tinfo_t()
    if not BOOL.get_named_type(til, "MACRO_BOOL"):
        ida.close_database(False)
        continue

    print(f"Processing {til_name}")

    for name in func_map:
        change_type(til, name, name, BOOL)
        change_type(til, name, name+"A", BOOL)
        change_type(til, name, name+"W", BOOL)

    idaapi.compact_til(til)
    if not os.path.exists("pc"):
        os.mkdir("pc")
    idaapi.store_til(til, "pc", til_name)

    del BOOL
    ida.close_database(False)