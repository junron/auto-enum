import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

try:
    import ida
except ImportError:
    logging.fatal(
        "This script requires the ida module to be installed. Please consult the IDADIR/idalib/README.txt file for instructions on how to install it."
    )
    exit()
import idaapi
from pathlib import Path
import argparse

from auto_enum import get_or_add_enum, FunctionMap

default_til_masks = {
    "windows": "mssdk*.til",
    "linux": "gnulnx*.til",
    #    "macos": "macos*.til", # Not supported yet, maybe just map it to linux
}

default_til_dir = idaapi.idadir("til")
default_idb = "../demo/demo"

config = argparse.ArgumentParser(
    description="Apply fixes to function signatures directly to the til files"
)

config.add_argument(
    "--platform",
    type=str,
    help="Platform type",
    choices=default_til_masks.keys(),
    default="windows",
)
config.add_argument(
    "--tilmask",
    type=str,
    help=f"Til mask (defaults to mssdk*.til or gnulnx*.til depending on --platform)",
    default=None,
)
config.add_argument(
    "--tildir",
    type=str,
    help="Path to the IDA til directory (defaults to the IDA til directory)",
    default=default_til_dir,
)
config.add_argument("--outdir", type=str, help="Output directory", default="out")
config.add_argument(
    "--idb",
    type=str,
    help="IDB file to use for processing the til files",
    default=default_idb,
)
config.add_argument(
    "--funcmap",
    type=Path,
    help="Path to the function map directory. Defaults to the data folder next to the script.",
    default=Path(__file__).parent / "data",
)
config.add_argument(
    "--overwrite",
    action="store_true",
    default=False,
    help="Overwrite existing ida files (will backup the original files), use with caution. You will likely need an administrator / root access to overwrite the files.",
)
config.add_argument("--loglevel", type=str, help="Log level", default="INFO")
config.epilog = "Example: python apply_to_til.py --platform windows"


def type_for_name(til: idaapi.til_t, s: str) -> idaapi.tinfo_t:
    named_type = idaapi.get_named_type(til, s, 0)
    if named_type is None:
        return None
    (code, type_str, fields_str, cmt, field_cmts, sclass, value) = named_type
    # logging.debug(f"{code=}, {type_str=}, {fields_str=}, {cmt=}, {field_cmts=}, {sclass=}, {value=}")
    t = idaapi.tinfo_t()
    # deserialize(self, til, ptype, pfields=None, pfldcmts=None, cmt=None) -> bool
    assert t.deserialize(til, type_str, fields_str)  # , field_cmts, cmt)
    return t


def change_type(
    til: idaapi.til_t, name: str, ida_name: str, BOOL: idaapi.tinfo_t, func_map
) -> bool:
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
            logging.error(f"Error setting symbol type for {name}: {err_str}")


class ida_opener:
    def __init__(self, idb: Path):
        self.idb = idb

    def __enter__(self):
        self.opened = ida.open_database(str(self.idb), False)
        return self.opened

    def __exit__(self, *args):
        ida.close_database(False)


def process_til(
    til_file: Path,
    platform_type: str,
    out_file: Path,
    idb: Path,
    func_map: FunctionMap,
):
    with ida_opener(idb) as opened:
        if opened != 0:
            logging.error(f"Failed to open {idb}")
            return False

        til = idaapi.load_til(str(til_file))
        if not til:
            logging.error(f"Failed to load til file {til_file}")
            return False

        BOOL = idaapi.tinfo_t()
        if not BOOL.get_named_type(til, "MACRO_BOOL"):
            logging.error("Failed to get BOOL type")
            return False

        logging.info(f"Processing {til_file}")

        get_or_add_enum.cache_clear()

        for name in func_map:
            change_type(til, name, name, BOOL, func_map)
            # Add A/W versions for windows
            if platform_type == "windows":
                change_type(til, name, name + "A", BOOL, func_map)
                change_type(til, name, name + "W", BOOL, func_map)

        idaapi.compact_til(til)

        out_file.parent.mkdir(parents=True, exist_ok=True)

        ok = idaapi.store_til(til, None, str(out_file))
        if not ok:
            logging.error(f"Failed to save til file to {out_file}")
            return False

        logging.info(f"Saved til file to {out_file}")
        return True


def main():
    args = config.parse_args()
    logging.getLogger().setLevel(args.loglevel)
    tildir = Path(args.tildir)
    tilmask = args.tilmask or default_til_masks[args.platform]

    function_map = FunctionMap(args.funcmap / args.platform)

    changed_files: "list[tuple[Path, Path]]" = []

    for old_til in tildir.rglob(tilmask):
        new_til = Path(args.outdir) / old_til.relative_to(tildir)
        ok = process_til(
            old_til,
            args.platform,
            new_til,
            Path(args.idb),
            function_map,
        )
        if ok:
            changed_files.append((old_til, new_til))

    if args.overwrite:
        # https://www.youtube.com/watch?v=yNY6ZstdUdY
        if (
            not input(
                f"Are you sure you want to overwrite the existing til files in {tildir}? (y/n)"
            )
            .lower()
            .startswith("y")
        ):
            logging.warning("Aborting")
            return

        for old_til, new_til in changed_files:
            backup = Path(str(old_til) + ".bak")
            if not backup.exists():
                old_til.rename(backup)
            else:
                logging.warning(f"Backup file {backup} already exists, skipping")

            old_til.write_bytes(new_til.read_bytes())


if __name__ == "__main__":
    main()
