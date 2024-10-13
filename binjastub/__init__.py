import os
import sys

lh_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "plugin")
sys.path.append(lh_path)

import binaryninja as bn
from enumlib.ui_plugins.binja_plugin import auto_enum
bn.PluginCommand.register("Auto Enum", "Automatically detect standard enums", auto_enum)