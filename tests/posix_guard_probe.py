"""Standard-library-only probe; generated commands use printf, never real SOS."""


def run(commands):
    import json
    import os
    import shlex
    import shutil
    import subprocess
    import tempfile

    directory = tempfile.mkdtemp(prefix="vb_sos_guard_")
    try:
        os.mkdir(os.path.join(directory, "rtl"))
        os.mkdir(os.path.join(directory, "package"))
        for name in ("rtl/good.v", "package/master.tag", "package/sidecar"):
            with open(os.path.join(directory, name), "w") as stream:
                stream.write("fixture\n")
        os.symlink(os.path.join(directory, "rtl/good.v"), os.path.join(directory, "link.v"))
        os.symlink(os.path.join(directory, "rtl"), os.path.join(directory, "alias"))
        quote = getattr(shlex, "quote", None)
        if quote is None:
            from pipes import quote
        expected = {"ordinary": 0, "directory": 65, "symlink": 65,
                    "oa_sidecar": 65, "symlink_parent": 65, "mixed": 65}
        results = {}
        for label, command in commands.items():
            assert command.startswith("cd /__VB_TEST_ROOT__ && ")
            command = command.replace("cd /__VB_TEST_ROOT__ && ", "cd " + quote(directory) + " && ", 1)
            process = subprocess.Popen(["sh", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True)
            stdout, stderr = process.communicate()
            assert process.returncode == expected[label], (label, process.returncode, stderr)
            assert (stdout == "co") if label == "ordinary" else not stdout, (label, stdout)
            results[label] = {"returncode": process.returncode, "mutation_reached": bool(stdout)}
        return json.dumps(results, sort_keys=True)
    finally:
        shutil.rmtree(directory)
