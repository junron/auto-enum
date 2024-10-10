import functools
import json
import os
import re
import string

from copy import deepcopy
from typing import Dict, List, Optional, Callable


class Argument:
    name: str
    has_enum: bool
    call_specific: bool
    type: Optional[str] = None
    enum: Optional[str] = None

    def __init__(self, data, call_specific=False):
        self.name = data["name"]
        if "enum" in data:
            self.has_enum = True
            self.enum = data["enum"]
            self.type = "int"
        else:
            self.has_enum = False
            self.type = data["type"]
        self.call_specific = call_specific

    def __copy__(self):
        return Argument({
            "name": self.name,
            ("enum" if self.has_enum else "type"): (self.enum if self.has_enum else self.type)
        }, call_specific=self.call_specific)
        
    def __repr__(self):
        if self.has_enum:
            return f"ENUM_{self.enum} {self.name}"
        return f"{self.type} {self.name}"


class Function:
    def __init__(self, loader: "FunctionLoader", name, arguments, varargs):
        self.name: str = name
        self.varargs = varargs
        self.arguments: List[Argument] = arguments
        self.concrete_arguments = {}
        self.loader = loader

    def with_concrete_arguments(self, loader: Callable[[int], int]) -> "Function":
        func2 = self.__copy__()
        if self.loader.special is None or self.name not in self.loader.special:
            return func2
        special_func_data = self.loader.special[self.name]
        arg_idx = special_func_data["primary_idx"]
        if arg_idx in func2.concrete_arguments:
            arg_val = func2.concrete_arguments[arg_idx]
        else:
            arg_val = loader(arg_idx)
        if arg_val is None:
            return func2
        func2.concrete_arguments |= {arg_idx: arg_val}
        target_arg_idx = special_func_data["secondary_idx"]
        if "options" in special_func_data:
            arg_data = special_func_data["options"]
            if str(arg_val) in arg_data and target_arg_idx < len(func2.arguments):
                enum_id = arg_data[str(arg_val)]
                func2.arguments[target_arg_idx].enum = enum_id
                func2.arguments[target_arg_idx].has_enum = True
                func2.arguments[target_arg_idx].type = 'int'
                func2.arguments[target_arg_idx].call_specific = True
        if "types" in special_func_data:
            arg_data = special_func_data["types"]
            if str(arg_val) in arg_data:
                if target_arg_idx < len(func2.arguments):
                    func2.arguments[target_arg_idx].type = arg_data[str(arg_val)]
                    func2.arguments[target_arg_idx].call_specific = True
                elif target_arg_idx == len(func2.arguments):
                    func2.arguments.append(Argument({
                        "name": "extra_arg",
                        "type": arg_data[str(arg_val)]
                    }, call_specific=True))
        return func2
        
    def __copy__(self):
        return Function(self.loader, self.name, deepcopy(self.arguments), self.varargs)
        
    def __repr__(self):
        args = [str(arg) for arg in self.arguments]
        if self.varargs:
            args.append("...")
        return f"{self.name}({', '.join(args)})"
        
        

class FunctionLoader:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        if os.path.exists(f"{self.data_dir}/special.json"):
            with open(f"{self.data_dir}/special.json", "r") as file:
                self.special = json.load(file)
        else:
            self.special = None

    def __iter__(self):
        for funcname in os.listdir(f"{self.data_dir}/functions"):
            if not funcname.endswith(".json"):
                continue
            yield funcname.split(".")[0]

    @functools.lru_cache()
    def __contains__(self, funcname: str):
        return os.path.exists(f"{self.data_dir}/functions/{funcname}.json")

    @functools.lru_cache()
    def __getitem__(self, funcname: str):
        if funcname not in self:
            raise KeyError(f"{funcname} not found!")
        with open(f"{self.data_dir}/functions/{funcname}.json", "r") as file:
            data = json.load(file)
            func = Function(self, data["name"], [Argument(arg) for arg in data["args"]], data["varargs"])
            func.name = data["name"]
            return func

class EnumLoader:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        with open(f"{self.data_dir}/enums.json") as f:
            self.enums = json.loads(f.read())
        

    def all_digits(self, val: str):
        return all(x in string.digits for x in val)
    
    def expand_enum(self, enum: Dict[str, int], enum_id: str) -> Dict[str, int]:
        items = list(enum.items())
        if not self.all_digits(enum_id):
            if re.search(r"_[0-9]+$", enum_id):
                enum_id = re.sub(r"_[0-9]+$", "", enum_id)
            for k, v in items:
                del enum[k]
                if k == "0":
                    enum["NULL"] = v
                else:
                    enum[f"{enum_id}_{k}"] = v
            return enum

        for k, v in items:
            if k == "0":
                del enum[k]
                enum["NULL"] = v
        return enum

    @functools.lru_cache()
    def __getitem__(self, name: str):
        enum = self.enums[name]
        return self.expand_enum(dict(enum), name)


class AutoEnum:
    functions: FunctionLoader
    enums: EnumLoader
    def __init__(self, platform: str):
        assert platform in ["windows", "linux"], "Supported platforms are windows or linux."
        self.platform = platform
        self.data_dir = os.path.join(os.path.dirname(__file__), "data", platform)
        self.functions = FunctionLoader(self.data_dir)
        self.enums = EnumLoader(self.data_dir)
