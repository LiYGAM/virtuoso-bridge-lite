import os
import shlex

import pytest

from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.virtuoso.sos import SOSWorkarea
from tests.posix_guard_probe import run


def guard_commands():
    class Owner:
        _timeout = 5

        @property
        def sos_runner(self):
            return self

        def run_command(self, command, *, timeout):
            self.command = command
            if "status -Nhdr" in command:
                return CommandResult(0, "f\t" + shlex.split(command)[-1] + "\n", "")
            return CommandResult(0, "", "")

    owner = Owner()
    area = SOSWorkarea(owner, "/__VB_TEST_ROOT__", soscmd="printf")
    commands = {}
    for label, paths in {"ordinary": "rtl/good.v", "directory": "rtl",
                         "symlink": "link.v", "oa_sidecar": "package/sidecar",
                         "symlink_parent": "alias/good.v", "mixed": ["rtl/good.v", "package/sidecar"]}.items():
        area.checkout(paths)
        commands[label] = owner.command
    return commands


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX filesystem and sh")
def test_generated_shell_guards_reject_nonordinary_files_before_write():
    run(guard_commands())
