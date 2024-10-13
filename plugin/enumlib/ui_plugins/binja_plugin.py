import binaryninja as bn
from enumlib import AutoEnum


def get_or_add_enum(bv: bn.BinaryView, autoenum: AutoEnum, enum_id: str):
    enum_name = f"ENUM_{enum_id}"
    if not bv.get_type_by_name(enum_name):
        enum = autoenum.enums[enum_id]
        enum_type = bn.EnumerationType.create(members=enum.items(), arch=bv.arch)

        bv.define_user_type(enum_name, enum_type)

    return enum_name


def auto_enum(bv: bn.BinaryView):
    bv.begin_undo_actions()
    try:
        platform = "windows" if bv.platform.name.lower() == "windows" else "linux"

        autoenum = AutoEnum(platform)

        for func in bv.functions:
            if func.name in autoenum.functions:
                map_func = autoenum.functions[func.name]
                changed = False
                func_type = func.type
                new_parameters = []
                params = func_type.parameters
                if not params:
                    for p in map_func.arguments:
                        t, _ = bv.parse_type_string(p.type)
                        params.append(bn.FunctionParameter(t, p.name))
                    changed = True
                for param in params:
                    arg = next((x for x in map_func.arguments if x.name == param.name), None)
                    if arg is not None and arg.enum is not None:
                        enum_name = get_or_add_enum(bv, autoenum, arg.enum)
                        enum_type = bv.get_type_by_name(enum_name)
                        if enum_type:
                            param = bn.FunctionParameter(enum_type, param.name)
                            changed = True
                    new_parameters.append(param)

                if changed:
                    print(f"Setting enums for {func.name}")
                    new_func_type = bn.FunctionType.create(
                        ret=func_type.return_value,
                        params=new_parameters,
                        calling_convention=func_type.calling_convention,
                        variable_arguments=func_type.has_variable_arguments or map_func.varargs,
                    )
                    func.set_user_type(new_func_type)
                if func.name in autoenum.functions.special:
                    for site in func.caller_sites:
                        call_insn = site.mlil
                        def arg_val_loader(arg_idx: int):
                            if arg_idx >= len(call_insn.params):
                                return None
                            arg = call_insn.params[arg_idx]
                            if arg.operation == bn.MediumLevelILOperation.MLIL_CONST:
                                return arg.constant
                            return None
                        original_func = autoenum.functions[func.name]
                        func2 = original_func.with_concrete_arguments(arg_val_loader)
                        special_new_params = list(new_parameters)
                        for i, arg in enumerate(func2.arguments):
                            if not arg.call_specific:
                                continue
                            if arg.has_enum and i < len(special_new_params):
                                enum_name = get_or_add_enum(bv, autoenum, arg.enum)
                                enum_type = bv.get_type_by_name(enum_name)
                                if enum_type:
                                    param = bn.FunctionParameter(enum_type, special_new_params[i].name)
                                    special_new_params[i] = param
                            if i == len(original_func.arguments):
                                if func2.varargs:
                                    try:
                                        t, _ = bv.parse_type_string(arg.type)
                                    except SyntaxError:
                                        print("Failed to load type for", arg.type)
                                        continue
                                    special_new_params.append(bn.FunctionParameter(t, arg.name))
                            elif arg.type != original_func.arguments[i].type and i < len(special_new_params):
                                t, _ = bv.parse_type_string(arg.type)
                                param = bn.FunctionParameter(t, special_new_params[i].name)
                                special_new_params[i] = param
                        special_new_func_type = bn.FunctionType.create(
                            ret=new_func_type.return_value,
                            params=special_new_params,
                            calling_convention=new_func_type.calling_convention,
                            variable_arguments=new_func_type.has_variable_arguments or map_func.varargs,
                        )
                        site.function.set_call_type_adjustment(site.address, special_new_func_type)
        bv.reanalyze()
    finally:
        bv.commit_undo_actions()