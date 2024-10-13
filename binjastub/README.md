# Auto Enum

![binja_demo](https://files.junron.dev/binja_demo.gif)

## Overview

Decompiled C code often contains "magic" constants that represent flags or options.
```c
int64_t buf = mmap(0, 0x1000, 7, 0x22, 0xffffffff, 0);
```

Auto Enum detects and demystifies these constants, converting them to human-readable symbols.

```c
int64_t buf = mmap(
    0,
    0x1000,
    PROT_WRITE | PROT_EXEC | PROT_READ,
    MAP_PRIVATE | MAP_ANON | MAP_FILE,
    0xffffffff, 0
);
```

Check out the [README](https://github.com/junron/auto-enum) on GitHub for more info!