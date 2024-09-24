# Auto Enum
IDA Plugin to automatically identify and set enums for standard functions

## Demo

### Linux

https://github.com/junron/auto-enum/assets/26194273/9e43f3ec-0722-4388-951a-b90bec5ab19b


See [`demo.c`](./demo/demo.c) for the source code.

### Windows


https://github.com/junron/auto-enum/assets/26194273/0c6a0f69-b9c0-42ea-b97b-5848b6f7c3a1

See [`demo-win.cpp`](./demo/demo-win.cpp) for the source code.


## Plugin Installation

Copy `plugin/*` to your IDA Plugin directory. No dependencies required.

## TIL patching

Auto-enum can be integrated directly into the type library (TIL) files, allowing for enum loading without the plugin's installation. However, per-call analysis will only be available if the plugin is installed.

To modify the TIL files, run the following commands in the `plugins` directory:
```shell
# Generate for linux
python3 apply_to_til.py --platform linux --overwrite
# Generate for Windows
python3 apply_to_til.py --platform windows --overwrite
```
Note that you must have IDA Pro 9 installed, with `idalib` activated.   

As the TIL files installed with IDA will be modified, ensure that you have a backup of the `til` directory, as well as sufficient permissions to modify files in the IDA installation directory.