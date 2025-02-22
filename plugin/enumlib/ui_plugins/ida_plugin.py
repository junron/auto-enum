import os.path
import traceback
import functools
import json
import enumlib

import idc
import idautils
import idaapi
import ida_typeinf
import ida_nalt
import ida_hexrays
import ida_funcs

# From https://github.com/tmr232/Sark/blob/main/sark/ui.py#L358
class ActionHandler(idaapi.action_handler_t):
    """A wrapper around `idaapi.action_handler_t`.

    The class simplifies the creation of UI actions in IDA >= 6.7.

    To create an action, simply create subclass and override the relevant fields
    and register it::

        class MyAction(ActionHandler):
            TEXT = "My Action"
            HOTKEY = "Alt+Z"

            def _activate(self, ctx):
                idaapi.msg("Activated!")

        MyAction.register()

    Additional Documentation:
        Introduction to `idaapi.action_handler_t`:
            http://www.hexblog.com/?p=886

        Return values for update (from the SDK):
            AST_ENABLE_ALWAYS     // enable action and do not call action_handler_t::update() anymore
            AST_ENABLE_FOR_IDB    // enable action for the current idb. Call action_handler_t::update() when a database is opened/closed
            AST_ENABLE_FOR_WIDGET // enable action for the current widget. Call action_handler_t::update() when a form gets/loses focus
            AST_ENABLE            // enable action - call action_handler_t::update() when anything changes

            AST_DISABLE_ALWAYS    // disable action and do not call action_handler_t::action() anymore
            AST_DISABLE_FOR_IDB   // analog of ::AST_ENABLE_FOR_IDB
            AST_DISABLE_FOR_WIDGET// analog of ::AST_ENABLE_FOR_WIDGET
            AST_DISABLE           // analog of ::AST_ENABLE
    """
    NAME = None
    TEXT = "Default. Replace me!"
    HOTKEY = ""
    TOOLTIP = ""
    ICON = -1

    @classmethod
    def get_name(cls):
        """Return the name of the action.

        If a name has not been set (using the `Name` class variable), the
        function generates a name based on the class name and id.
        :return: action name
        :rtype: str
        """
        if cls.NAME is not None:
            return cls.NAME

        return "{}:{}".format(cls.__name__, id(cls))

    @classmethod
    def get_desc(cls):
        """Get a descriptor for this handler."""
        name = cls.get_name()
        text = cls.TEXT
        handler = cls()
        hotkey = cls.HOTKEY
        tooltip = cls.TOOLTIP
        icon = cls.ICON
        action_desc = idaapi.action_desc_t(
            name,
            text,
            handler,
            hotkey,
            tooltip,
            icon,
        )
        return action_desc

    @classmethod
    def register(cls):
        """Register the action.

        Each action MUST be registered before it can be used. To remove the action
        use the `unregister` method.
        """
        action_desc = cls.get_desc()

        return idaapi.register_action(action_desc)

    @classmethod
    def unregister(cls):
        """Unregister the action.

        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            self._activate(ctx)
            return 1
        except:
            trace = traceback.format_exc()
            idaapi.msg("Action {!r} failed to activate. Traceback:\n{}".format(self.get_name(), trace))
            return 0

    def update(self, ctx):
        """Update the action.

        Optionally override this function.
        See IDA-SDK for more information.
        """
        return idaapi.AST_ENABLE_ALWAYS

    def _activate(self, ctx):
        """Activate the action.

        This function contains the action code itself. You MUST implement
        it in your class for the action to work.

        Args:
            ctx: The action context passed from IDA.
        """
        raise NotImplementedError()


def make_import_names_callback(library_calls, library_addr):
    """ Return a callback function used by idaapi.enum_import_names(). """

    def callback(ea, name, ordinal):
        """ Callback function to retrieve code references to library calls. """
        if "@" in name:
            name = name.split("@")[0]
            ea = next(idautils.CodeRefsTo(ea, 0), None)
            if ea is None:
                return True
            func = ida_funcs.get_func(ea)
            if func is not None:
                ea = next(func.addresses())

        wrapper = idc.get_name_ea_simple("." + name)    
        if wrapper != idc.BADADDR:
            ea = wrapper
        else:
            wrapper = idc.get_name_ea_simple(name)
            if wrapper != idc.BADADDR:
                ea = wrapper
        library_calls[name] = []
        library_addr[name] = ea
        for ref in idautils.CodeRefsTo(ea, 0):
            library_calls[name].append(ref)
        return True  # True -> Continue enumeration

    return callback


def get_imports(library_calls, library_addr):
    """ Populate dictionaries with import information. """
    import_names_callback = make_import_names_callback(library_calls,
                                                       library_addr)
    for i in range(0, idaapi.get_import_module_qty()):
        idaapi.enum_import_names(i, import_names_callback)


def get_funcinfo(funcptr_addr):
    tif = ida_typeinf.tinfo_t()
    funcdata = ida_typeinf.func_type_data_t()

    if not ida_nalt.get_tinfo(tif, funcptr_addr):
        return None, None
    if not tif.is_funcptr():
        if tif.is_func():
            tif.get_func_details(funcdata)
            return False, funcdata
        return None, None
    if not tif.get_pointed_object().get_func_details(funcdata):
        return None, None
    return True, funcdata


@functools.lru_cache()
def get_or_add_enum(auto_enum: enumlib.AutoEnum, enum_id: str, til: idaapi.til_t=None):
    enum_name = f"ENUM_{enum_id}"
    ida_enum_id = idc.get_enum(enum_name)
    if ida_enum_id == idaapi.BADADDR:
        ida_enum_id = idc.add_enum(-1, enum_name, idaapi.hex_flag())
        enum = auto_enum.enums[enum_id]
        ida_typeinf.begin_type_updating(ida_typeinf.UTP_ENUM)
        for k, v in enum.items():
            res = idc.add_enum_member(ida_enum_id, k, v, -1)
            append = 1
            while res != 0 and append < 10:
                res = idc.add_enum_member(ida_enum_id, f"{k}_{append}", v, -1)
                append += 1
        ida_typeinf.end_type_updating(ida_typeinf.UTP_ENUM)
        if til:
            tif = idaapi.tinfo_t()
            tif.get_type_by_tid(ida_enum_id)
            tif.set_named_type(til, enum_name, idaapi.NTF_REPLACE | idaapi.NTF_COPY)
        return enum_name
    return enum_name

class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        type = idaapi.get_widget_type(form)
        if type == idaapi.BWN_DISASM or type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, AutoEnum.get_name(), '')

class AutoEnum(ActionHandler):
    TEXT = "Auto Enum"

    def _activate(self, ctx):
        main()

class Hooks2(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        type = idaapi.get_widget_type(form)
        if type == idaapi.BWN_DISASM or type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, AutoEnumPerCall.get_name(), '')

class AutoEnumPerCall(ActionHandler):
    TEXT = "Auto Enum (per-call annotation)"

    def _activate(self, ctx):
        handle_call_specific_enums()


class AutoEnumPlugin(idaapi.plugin_t):
    flags = 0
    comment = 'Automatically detect standard enums'
    help = 'Automatically detect standard enums'
    wanted_name = 'Auto Enum'

    def init(self):
        print("[AutoEnum] Plugin loaded!")
        AutoEnum.register()
        AutoEnumPerCall.register()
        self.hooks = Hooks()
        self.hooks.hook()
        self.hooks2 = Hooks2()
        self.hooks2.hook()

        return idaapi.PLUGIN_KEEP
    
    def term(self):
        self.hooks.unhook()
        self.hooks2.unhook()
        AutoEnum.unregister()
        AutoEnumPerCall.unregister()
    
    def run(self, arg):
        pass

def main():
    handle = ida_hexrays.open_pseudocode(idc.here(), 0)
    library_calls = {}
    library_addr = {}
    get_imports(library_calls, library_addr)
    platform = "windows"
    if "ELF" in idaapi.get_file_type_name():
        platform = "linux"
    auto_enum = enumlib.AutoEnum(platform)
    functions = list(library_addr.items())
    BOOL = ida_typeinf.tinfo_t()
    BOOL.get_named_type(idaapi.get_idati(), "MACRO_BOOL")
    for name, addr in functions:
        is_ptr, funcdata = get_funcinfo(addr)
        if name[:-1] in auto_enum.functions:
            library_addr[name[:-1]] = library_addr[name]
            name = name[:-1]
        func_has_enums = name in auto_enum.functions
        changed = False
        if not funcdata:
            continue
        for i, arg in enumerate(funcdata):
            if arg.type.is_ptr():
                continue
            type_name = arg.type.get_type_name()
            if type_name is not None and type_name.lower() in ["bool"]:
                arg.type = BOOL
                changed = True
            elif func_has_enums and arg.type.is_integral() and not arg.type.is_enum():
                func = auto_enum.functions[name]
                matching_arg = next((x for x in func.arguments if x.name == arg.name), None)
                if matching_arg is None:
                    if len(func.arguments) > i:
                        matching_arg = func.arguments[i]
                if matching_arg and matching_arg.enum is not None:
                    enum_name = get_or_add_enum(auto_enum, matching_arg.enum)
                    enum_type = ida_typeinf.tinfo_t()
                    enum_type.get_named_type(idaapi.get_idati(), enum_name)
                    arg.type = enum_type
                    changed = True
        if changed:
            print(f"Setting enums for {name}")
            ti = idaapi.tinfo_t()
            ti.create_func(funcdata)
            if is_ptr:
                tip = idaapi.tinfo_t()
                tip.create_ptr(ti)
                ida_typeinf.apply_tinfo(addr, tip, idaapi.TINFO_DEFINITE)
            else:
                ida_typeinf.apply_tinfo(addr, ti, idaapi.TINFO_DEFINITE)
    handle.refresh_view(True)

def find_parent_expr(cfunc, ea, expr_types) -> ida_hexrays.cexpr_t:
    citem: ida_hexrays.citem_t = cfunc.body.find_closest_addr(ea)
    cexpr: ida_hexrays.cexpr_t = citem.cexpr
    depth = 0
    while cexpr.op not in expr_types and depth < 5:
        citem = cfunc.body.find_parent_of(citem)
        if citem is None:
            return None
        cexpr = citem.cexpr
        depth += 1
    
    if depth == 5:
        return None
    
    return cexpr

def get_call(cfunc, ea) -> ida_hexrays.cexpr_t:
    return find_parent_expr(cfunc, ea, [ida_hexrays.cot_call])

class type_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, mapping):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.mapping = mapping

    def modify_lvars(self, lvars):
        for lvar in lvars.lvvec:
            if lvar.name in self.mapping:
                lvar.type = self.mapping[lvar.name]
        return True

def set_type(cfunc: ida_hexrays.cfunc_t, cexpr: ida_hexrays.cexpr_t, new_type: str):
    if new_type and new_type[-1] != ";":
        new_type += ";"
    tinfo = ida_typeinf.tinfo_t()
    result = ida_typeinf.parse_decl(tinfo, None, new_type, ida_typeinf.PT_TYP|ida_typeinf.PT_SIL)
    dereferenced = False
    def dereference():
        nonlocal dereferenced
        if dereferenced:
            return tinfo
        if not tinfo.is_ptr():
            raise TypeError(f"Attempt to set non pointer type '{new_type}' on reference at 0x{cexpr.ea:x}")
        dereferenced = True
        return tinfo.get_pointed_object()
    
    if result is None:
        raise TypeError(f"Failed to parse type '{new_type}'")
    if cexpr.opname == "cast":
        cexpr = cexpr.x
    if cexpr.opname == "ref":
        tinfo = dereference()
        cexpr = cexpr.x
    if cexpr.opname == "obj":
        tinfo = dereference()
        ida_typeinf.apply_tinfo(cexpr.obj_ea, tinfo, ida_typeinf.TINFO_DEFINITE)
        return
    elif cexpr.opname == "var":
        func_ea = cfunc.entry_ea
        var_name = cexpr.dstr()
        ida_hexrays.rename_lvar(func_ea, var_name, var_name + "_rt")
        ida_hexrays.modify_user_lvars(func_ea, type_modifier_t({
            (var_name + "_rt"): tinfo
        }))
        ida_hexrays.rename_lvar(func_ea, var_name + "_rt", var_name)
        return
    elif cexpr.opname == "num":
        # No need to do anything here, probably gonna set an enum on it later
        return
    raise TypeError(f"Don't know how to set type for a '{cexpr.opname}' at 0x{cexpr.ea:x}")

def handle_call_specific_enums():
    # Only updates for single function (maybe)
    handle = ida_hexrays.open_pseudocode(idc.here(), 0)
    cfunc = ida_hexrays.decompile(idc.here())
    if cfunc is None:
        return
    library_calls = {}
    library_addr = {}
    get_imports(library_calls, library_addr)
    if "ELF" in idaapi.get_file_type_name():
        platform = "linux"
    else:
        # Windows not supported at the moment
        return
    auto_enum = enumlib.AutoEnum(platform)
    for func_name in auto_enum.functions.special.keys():
        if func_name not in library_calls:
            continue
        func = auto_enum.functions[func_name]
        for call_ea in library_calls[func_name]:
            call = get_call(cfunc, call_ea)
            if call is None:
                continue
            args = call.a
            def arg_val_loader(arg_idx: int):
                if arg_idx >= len(args):
                    return None
                arg_val = args[arg_idx]
                if arg_val.opname != 'num':
                    if arg_val.opname == 'cast' and arg_val.x.opname == 'num':
                        arg_val = arg_val.x
                    else:
                        return None
                return arg_val.numval()
            
            func2 = func.with_concrete_arguments(arg_val_loader)

            for i, arg in enumerate(func2.arguments):
                if not arg.call_specific:
                    continue
                if i == len(func.arguments) or arg.type != func.arguments[i].type:
                    try:
                        set_type(cfunc, args[i], arg.type)
                    except Exception as e:
                        print("Failed to set type", e)
                if arg.has_enum:
                    enum_id = arg.enum
                    enum_name = get_or_add_enum(auto_enum, enum_id)
                    enum_id = idc.get_enum(enum_name)
                    try:
                        idc.op_enum(args[i].ea, -1, enum_id)
                    except:
                        # IDA 8
                        idc.op_enum(args[i].ea, -1, enum_id, 0)

    handle.refresh_view(True)
