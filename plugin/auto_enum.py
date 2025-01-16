def PLUGIN_ENTRY():
    from enumlib.ui_plugins.ida_plugin import AutoEnumPlugin
    return AutoEnumPlugin()

try:
    import idaapi
except:
    try:
        import binaryninja as bn
        from enumlib.ui_plugins.binja_plugin import auto_enum
        bn.PluginCommand.register("Auto Enum", "Automatically detect standard enums", auto_enum)
    except:
        pass