"""Generate src/hozo/syscalls.json from the host's kernel headers.

x86_64  <- /usr/include/asm/unistd_64.h  (arch-specific table)
aarch64 <- asm-generic/unistd.h via the C preprocessor (arm64 uses the generic table)
"""

import json
import re
import subprocess
from pathlib import Path

DEFINE = re.compile(r"^#define\s+__NR_(\w+)\s+(\d+)\s*$", re.M)
SKIP = re.compile(r"^(syscalls|arch_specific_syscall)$")


def parse(text: str) -> dict[str, int]:
    out = {}
    for name, number in DEFINE.findall(text):
        if SKIP.match(name):
            continue
        out[name] = int(number)
    return out


def generic() -> dict[str, int]:
    proc = subprocess.run(
        ["gcc", "-E", "-dM", "-x", "c", "-"],
        input="#include <asm-generic/unistd.h>\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return parse(proc.stdout)


def main() -> None:
    x86_64 = parse(Path("/usr/include/asm/unistd_64.h").read_text())
    aarch64 = generic()
    assert x86_64["io_uring_setup"] == 425, x86_64.get("io_uring_setup")
    assert aarch64["bpf"] == 280, aarch64.get("bpf")
    assert len(x86_64) > 300 and len(aarch64) > 300, (len(x86_64), len(aarch64))

    table = {arch: dict(sorted(names.items())) for arch, names in (("x86_64", x86_64), ("aarch64", aarch64))}
    out = Path(__file__).resolve().parent.parent / "src" / "hozo" / "syscalls.json"
    out.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n")
    print(f"{out}: x86_64={len(x86_64)} aarch64={len(aarch64)}")


if __name__ == "__main__":
    main()
