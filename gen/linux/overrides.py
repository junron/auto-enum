disallow_headers = [
    # I don't have the required headers
    "numaif",
    "perfmon",
    "linux/module.h",
    "sys/cachectl.h",
]

additional_headers = {
    "AT_SYMLINK_NOFOLLOW": "#include <linux/fcntl.h>\n",
    "IPC_INFO": "#define IPC_INFO 3\n",
    "PROT_SEM": "#include <asm/mman.h>\n",
    "SEEK_HOLE": "#include <linux/fs.h>\n",
    "MFD_ALLOW_SEALING": "#include <linux/memfd.h>\n",
    "O_RDWR": "#define _GNU_SOURCE\n#include <fcntl.h>\n",
    "O_LARGEFILE": "#define O_LARGEFILE 00100000\n",
    "MADV_SOFT_OFFLINE": "#include <linux/mman.h>\n",
    "SHM_HUGE_2MB":"#define SHM_HUGE_2MB    (21 << 26)\n",
    "MAP_32BIT":"#define MAP_32BIT 0x40\n",
    "MAP_HUGE_2MB":"#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)\n",
}

replacement_headers = {
    "CLONE_NEWPID": "#include <linux/sched.h>\n",
    "SCHED_BATCH": "#include <linux/sched.h>\n",
    "SPLICE_F_NONBLOCK": "#define SPLICE_F_MOVE	(0x01)\n#define SPLICE_F_NONBLOCK (0x02)\n#define SPLICE_F_MORE	(0x04)\n#define SPLICE_F_GIFT	(0x08)\n",
    # _GNU_SOURCE must be defined
    "MSG_EXCEPT": "#include <linux/msg.h>\n",
    "SYNC_FILE_RANGE_WRITE": "#define SYNC_FILE_RANGE_WAIT_BEFORE	1\n#define SYNC_FILE_RANGE_WRITE		2\n#define SYNC_FILE_RANGE_WAIT_AFTER	4\n",
    "F_SETLEASE": "#include <linux/fcntl.h>\n"
}

remap_value = {
    # > In the Linux kernel source code, the SCHED_OTHER policy is
    # > actually named SCHED_NORMAL.
    "SCHED_OTHER": "SCHED_NORMAL",
    # > This feature is specific to the PowerPC architecture
    "PROT_SAO": None,
    # Not supported by kernel
    "MAP_UNINITIALIZED": None,
    # Removed in linux 2.6.38
    "CLONE_STOPPED": None,
    # Removed in linux 2.5.15
    "CLONE_PID": None,
    # This flag is equivalent to (AI_ADDRCONFIG | AI_V4MAPPED).
    "AI_DEFAULT": None,
    # I could not find its value anywhere
    "SIG_HOLD": None,
}

remap = {
    "fcntl": {
        # Parsing is hard
        "fd": "cmd"
    },
    "lseek": {"fd": None, "rename": ["fseek", "lseek"]},
    "flock": {"fd": None},
    "epoll_create": {"rename": []},
    "open": {"rename": ["open", "openat"]},
}

custom = {
    "socket": {
        "args": {
            "domain": [
                "AF_MPLS",
                "AF_UNIX",
                "AF_BLUETOOTH",
                "AF_INET6",
                "AF_LOCAL",
                "AF_INET",
                "AF_KEY",
                "AF_IB",
                "AF_RDS",
                "AF_TIPC",
                "AF_NETLINK",
                "AF_VSOCK",
                "AF_CAN",
                "AF_KCM",
                "AF_X25",
                "AF_AX25",
                "AF_IPX",
                "AF_DECnet",
                "AF_PACKET",
                "AF_ALG",
                "AF_APPLETALK",
                "AF_PPPOX",
                "AF_XDP",
                "AF_LLC",
            ]
        }
    },
    "prctl": {
        "args": {
            "option": [
                "PR_CAP_AMBIENT",
                "PR_CAPBSET_READ",
                "PR_CAPBSET_DROP",
                "PR_SET_CHILD_SUBREAPER",
                "PR_GET_CHILD_SUBREAPER",
                "PR_SET_DUMPABLE",
                "PR_GET_DUMPABLE",
                "PR_SET_ENDIAN",
                "PR_GET_ENDIAN",
                "PR_SET_FP_MODE",
                "PR_GET_FP_MODE",
                "PR_SET_FPEMU",
                "PR_GET_FPEMU",
                "PR_SET_FPEXC",
                "PR_GET_FPEXC",
                "PR_SET_IO_FLUSHER",
                "PR_SET_KEEPCAPS",
                "PR_GET_KEEPCAPS",
                "PR_MCE_KILL",
                "PR_MCE_KILL_GET",
                "PR_SET_MM",
                "PR_MPX_DISABLE_MANAGEMENT",
                "PR_SET_NAME",
                "PR_GET_NAME",
                "PR_SET_NO_NEW_PRIVS",
                "PR_GET_NO_NEW_PRIVS",
                "PR_PAC_RESET_KEYS",
                "PR_SET_PDEATHSIG",
                "PR_GET_PDEATHSIG",
                "PR_SET_PTRACER",
                "PR_SET_SECCOMP",
                "PR_GET_SECCOMP",
                "PR_SET_SECUREBITS",
                "PR_GET_SECUREBITS",
                "PR_GET_SPECULATION_CTRL",
                "PR_SPEC_DISABLE_NOEXEC",
                "PR_SET_SPECULATION_CTRL",
                "PR_SPEC_INDIRECT_BRANCH",
                "PR_SPEC_DISABLE_NOEXEC",
                "PR_SVE_SET_VL",
                "PR_SVE_GET_VL",
                "PR_SET_SYSCALL_USER_DISPATCH",
                "PR_SET_TAGGED_ADDR_CTRL",
                "PR_GET_TAGGED_ADDR_CTRL",
                "PR_TASK_PERF_EVENTS_DISABLE",
                "PR_TASK_PERF_EVENTS_ENABLE",
                "PR_SET_THP_DISABLE",
                "PR_GET_THP_DISABLE",
                "PR_GET_TID_ADDRESS",
                "PR_SET_TIMERSLACK",
                "PR_GET_TIMERSLACK",
                "PR_SET_TIMING",
                "PR_GET_TIMING",
                "PR_SET_TSC",
                "PR_GET_TSC",
            ]
        },
        "prefix": "#include <sys/prctl.h>\n#include <linux/seccomp.h>\n",
    },
    "open": {
        "args": {
            "oflag": [
                "O_RSYNC",
                "O_WRONLY",
                "O_DIRECT",
                "O_DIRECTORY",
                "O_SYNC",
                "O_DSYNC",
                "O_RDONLY",
                "O_CREAT",
                "O_TRUNC",
                "O_RDWR",
                "O_CLOEXEC",
                "O_NOFOLLOW",
                "O_APPEND",
                "O_LARGEFILE",
                "O_ASYNC",
                "O_NDELAY",
                "O_TMPFILE",
                "O_NOATIME",
                "O_EXCL",
                "O_PATH",
                "O_NONBLOCK",
                "O_NOCTTY",
            ],
            "mode": [
                "S_IRWXU",
                "S_IRWXG",
                "S_IROTH",
                "S_IWOTH",
                "S_IXGRP",
                "S_ISGID",
                "S_IWUSR",
                "S_ISUID",
                "S_IWGRP",
                "S_ISVTX",
                "S_IXUSR",
                "S_IRWXO",
                "S_IRUSR",
                "S_IXOTH",
                "S_IRGRP",
            ],
        },
        "prefix": "#define _GNU_SOURCE\n#include <fcntl.h>\n",
    },
    "getaddrinfo_a": {
        "args": {
            "mode": [
                "GAI_NOWAIT",
                "GAI_WAIT",
            ]
        },
        "prefix": "#define _GNU_SOURCE\n#include <netdb.h>\n",
    },
}
