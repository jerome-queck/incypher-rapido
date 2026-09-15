"""Fail-closed Linux confinement for the descriptor-only artifact worker."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
import sys
import sysconfig
from pathlib import Path


class SandboxUnavailable(RuntimeError):
    """Required production confinement could not be installed."""


_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_JGE = 0x30
_BPF_K = 0x00
_BPF_RET = 0x06
_X32_SYSCALL_BIT = 0x40000000

_PROCESS_GROUP_SYSCALLS = {
    "x86_64": frozenset({109, 112}),
    "aarch64": frozenset({154, 157}),
}

_ARCHITECTURES = {
    "x86_64": (
        0xC000003E,
        {
            41,
            42,
            43,
            44,
            45,
            46,
            47,
            48,
            49,
            50,
            51,
            52,
            53,
            54,
            55,
            288,
            299,
            307,
            425,
            426,
            427,
        }
        | _PROCESS_GROUP_SYSCALLS["x86_64"],
    ),
    "aarch64": (
        0xC00000B7,
        {
            198,
            199,
            200,
            201,
            202,
            203,
            204,
            205,
            206,
            207,
            208,
            209,
            210,
            211,
            212,
            242,
            243,
            269,
            425,
            426,
            427,
        }
        | _PROCESS_GROUP_SYSCALLS["aarch64"],
    ),
}


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _checked(result: int, action: str) -> int:
    if result < 0:
        code = ctypes.get_errno()
        raise SandboxUnavailable(f"{action} failed with errno {code}")
    return result


def _runtime_paths() -> tuple[str, ...]:
    executable = Path(sys.executable).resolve()
    paths = {str(Path(__file__).resolve().parent), str(executable)}
    for prefix in {executable.parent.parent, Path(sys.base_prefix)}:
        for library in prefix.glob("lib/libpython*.so*"):
            paths.add(str(library.resolve()))
    venv_configuration = Path(sys.prefix) / "pyvenv.cfg"
    if venv_configuration.exists():
        paths.add(str(venv_configuration.resolve()))
    configured = sysconfig.get_paths()
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        value = configured.get(name)
        if value:
            paths.add(os.path.realpath(value))
    paths.update(
        path
        for path in (
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/usr/share/tesseract-ocr",
            "/sys/devices/system/cpu/possible",
            "/etc/ld.so.cache",
            "/dev/null",
            "/usr/bin/tesseract",
        )
        if os.path.exists(path)
    )
    normalized = []
    for path in sorted(paths):
        real = os.path.realpath(path)
        if real == "/" or any(
            real == root or real.startswith(root + "/") for root in ("/auth", "/state")
        ):
            raise SandboxUnavailable("artifact runtime path is not safely confined")
        if os.path.exists(real):
            normalized.append(real)
    return tuple(normalized)


def _install_landlock(scratch_fd: int) -> int:
    libc = _libc()
    create_number, add_number, restrict_number = 444, 445, 446
    abi = _checked(
        libc.syscall(create_number, 0, 0, _LANDLOCK_CREATE_RULESET_VERSION),
        "Landlock ABI query",
    )
    handled = (
        _LANDLOCK_ACCESS_FS_EXECUTE
        | _LANDLOCK_ACCESS_FS_WRITE_FILE
        | _LANDLOCK_ACCESS_FS_READ_FILE
        | _LANDLOCK_ACCESS_FS_READ_DIR
        | _LANDLOCK_ACCESS_FS_REMOVE_DIR
        | _LANDLOCK_ACCESS_FS_REMOVE_FILE
        | _LANDLOCK_ACCESS_FS_MAKE_CHAR
        | _LANDLOCK_ACCESS_FS_MAKE_DIR
        | _LANDLOCK_ACCESS_FS_MAKE_REG
        | _LANDLOCK_ACCESS_FS_MAKE_SOCK
        | _LANDLOCK_ACCESS_FS_MAKE_FIFO
        | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | _LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi >= 2:
        handled |= _LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        handled |= _LANDLOCK_ACCESS_FS_TRUNCATE
    ruleset_attr = _RulesetAttr(handled)
    ruleset = _checked(
        libc.syscall(create_number, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0),
        "Landlock ruleset creation",
    )
    try:
        for path in _runtime_paths():
            metadata = os.stat(path)
            access = _LANDLOCK_ACCESS_FS_READ_FILE | _LANDLOCK_ACCESS_FS_EXECUTE
            if stat.S_ISDIR(metadata.st_mode):
                access |= _LANDLOCK_ACCESS_FS_READ_DIR
            elif path == "/dev/null":
                access |= _LANDLOCK_ACCESS_FS_WRITE_FILE
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = _PathBeneathAttr(access, parent)
                _checked(
                    libc.syscall(
                        add_number,
                        ruleset,
                        _LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(rule),
                        0,
                    ),
                    "Landlock rule installation",
                )
            finally:
                os.close(parent)
        scratch_access = (
            _LANDLOCK_ACCESS_FS_WRITE_FILE
            | _LANDLOCK_ACCESS_FS_READ_FILE
            | _LANDLOCK_ACCESS_FS_READ_DIR
            | _LANDLOCK_ACCESS_FS_REMOVE_DIR
            | _LANDLOCK_ACCESS_FS_REMOVE_FILE
            | _LANDLOCK_ACCESS_FS_MAKE_DIR
            | _LANDLOCK_ACCESS_FS_MAKE_REG
        )
        if abi >= 2:
            scratch_access |= _LANDLOCK_ACCESS_FS_REFER
        if abi >= 3:
            scratch_access |= _LANDLOCK_ACCESS_FS_TRUNCATE
        scratch_rule = _PathBeneathAttr(scratch_access, scratch_fd)
        _checked(
            libc.syscall(
                add_number,
                ruleset,
                _LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(scratch_rule),
                0,
            ),
            "Landlock scratch rule installation",
        )
        _checked(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no-new-privileges")
        _checked(libc.syscall(restrict_number, ruleset, 0), "Landlock activation")
    finally:
        os.close(ruleset)
    return abi


def _seccomp_instructions(machine: str) -> list[_SockFilter]:
    if machine not in _ARCHITECTURES:
        raise SandboxUnavailable(f"unsupported seccomp architecture: {machine}")
    audit_arch, denied = _ARCHITECTURES[machine]
    instructions = [
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4),
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, audit_arch),
        _SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0),
    ]
    if machine == "x86_64":
        # x32 shares AUDIT_ARCH_X86_64 but tags syscall numbers. Reject the
        # entire ABI before native-number checks and the terminal allow.
        instructions.extend(
            (
                _SockFilter(_BPF_JMP | _BPF_JGE | _BPF_K, 0, 1, _X32_SYSCALL_BIT),
                _SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EACCES),
            )
        )
    for number in sorted(denied):
        instructions.extend(
            (
                _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 1, number),
                _SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EACCES),
            )
        )
    instructions.append(_SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW))
    return instructions


def _install_seccomp_filter() -> str:
    machine = platform.machine().lower()
    instructions = _seccomp_instructions(machine)
    program_type = _SockFilter * len(instructions)
    program_data = program_type(*instructions)
    program = _SockFprog(len(instructions), program_data)
    libc = _libc()
    _checked(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no-new-privileges")
    _checked(
        libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program)),
        "seccomp activation",
    )
    return machine


def apply_artifact_sandbox(source_fd: int, scratch_fd: int) -> dict[str, object]:
    """Constrain Linux worker/descendants to fixed files, group, and no networking."""
    if sys.platform != "linux":
        return {"platform": sys.platform, "enforced": False}
    try:
        metadata = os.fstat(source_fd)
    except OSError as exc:
        raise SandboxUnavailable("source descriptor is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SandboxUnavailable("source descriptor is not a regular file")
    try:
        scratch = os.fstat(scratch_fd)
    except OSError as exc:
        raise SandboxUnavailable("scratch descriptor is unavailable") from exc
    if not stat.S_ISDIR(scratch.st_mode):
        raise SandboxUnavailable("scratch descriptor is not a directory")
    abi = _install_landlock(scratch_fd)
    machine = _install_seccomp_filter()
    return {
        "platform": "linux",
        "enforced": True,
        "landlock_abi": abi,
        "arch": machine,
        "process_group_locked": True,
    }


__all__ = ["SandboxUnavailable", "apply_artifact_sandbox"]
