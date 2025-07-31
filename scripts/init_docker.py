# Init the docker container
# It will:
# 1. Git clone the Linux kernel source code
# 2. Prepare the LLVM source code

import subprocess as sp
from pathlib import Path

import yaml

llvm_path = "/app/llvm"
linux_path = "/app/linux"
key_file_path = "/app/llm_keys.yaml"

gen_result_path = "/app/result-generate"
refine_result_path = "/app/result-refine"
triage_result_path = "/app/result-triage"

model = "o3-mini"

generate_config_in_docker = {
    "result_dir": gen_result_path,
    "LLVM_dir": llvm_path,
    "linux_dir": linux_path,
    "checker_nums": 10,
    "key_file": key_file_path,
    "model": model,
}

refine_config_in_docker = {
    "result_dir": refine_result_path,
    "LLVM_dir": llvm_path,
    "linux_dir": linux_path,
    "checker_nums": 10,
    "key_file": key_file_path,
    "model": model,
    "jobs": 32,
    "scan_timeout": 3600,
    "scan_commit": "v6.11",
}

triage_config_in_docker = {
    "result_dir": triage_result_path,
    "LLVM_dir": llvm_path,
    "linux_dir": linux_path,
    "checker_nums": 10,
    "key_file": key_file_path,
    "model": model,
}

key_config_in_docker = {"openai_key": "XXX"}


def init_docker():
    # 1. Git clone the Linux kernel source code
    res = sp.run(
        ["git", "clone", "https://github.com/torvalds/linux.git", linux_path],
        cwd=Path("/app"),
    )
    if res.returncode != 0:
        raise RuntimeError("Failed to clone Linux kernel source code")

    # 2. Prepare the LLVM source code
    res = sp.run(["python3", "scripts/setup_llvm.py", llvm_path])
    if res.returncode != 0:
        raise RuntimeError("Failed to prepare LLVM source code")

    # 3. Copy the key file
    with open(key_file_path, "w") as f:
        yaml.dump(key_config_in_docker, f)

    # 4. Generate the config file
    with open("/app/config-generate.yaml", "w") as f:
        yaml.dump(generate_config_in_docker, f)

    # 5. Generate the refine config file
    with open("/app/config-refine.yaml", "w") as f:
        yaml.dump(refine_config_in_docker, f)
    with open("/app/config-refine-debug.yaml", "w") as f:
        refine_config_in_docker["result_dir"] = "/app/result-refine-debug"
        refine_config_in_docker["scan_commit"] = "v6.9"
        yaml.dump(refine_config_in_docker, f)

    # 6. Generate the triage config file
    with open("/app/config-triage.yaml", "w") as f:
        yaml.dump(triage_config_in_docker, f)
    with open("/app/config-triage-debug.yaml", "w") as f:
        triage_config_in_docker["result_dir"] = "/app/result-triage-debug"
        yaml.dump(triage_config_in_docker, f)


if __name__ == "__main__":
    init_docker()
