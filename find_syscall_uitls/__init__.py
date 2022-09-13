
from find_syscall_uitls.tables.arm64 import syscalls_arm64
from find_syscall_uitls.tables.arm import syscalls_arm

# class NoSystemCall(Exception):
#     """Exception not system call."""

#     pass


# class NotArch(Exception):
#     """Exception not arch."""
#     pass

class syscalls(dict):
    def __init__(self):
        self.syscalls = {
            "archs": {
                 "arm64": syscalls_arm64,
                 "arm": syscalls_arm
            }
        }

    def get(self, arch: str, num:int):
        try:
            return self.syscalls["archs"][arch][str(num)]
        except KeyError:
            pass
        return ""