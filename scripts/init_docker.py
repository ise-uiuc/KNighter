# Init the docker container
# It will:
# 1. Git clone the Linux kernel source code
# 2. Prepare the LLVM source code

import subprocess as sp
from pathlib import Path

import yaml

generate_config_in_docker = {
    "result_dir": "/app/result-generate",
    "LLVM_dir": "/app/llvm",
    "linux_dir": "/app/linux",
    "checker_nums": 10,
    "key_file": "/app/llm_keys.yaml",
    "model": "o3-mini",
}

refine_config_in_docker = {
    "result_dir": "/app/result-refine",
    "LLVM_dir": "/app/llvm",
    "linux_dir": "/app/linux",
    "checker_nums": 10,
    "key_file": "/app/llm_keys.yaml",
    "model": "o3-mini",
}

key_config_in_docker = {"openai_key": "XXX"}


def init_docker():
    # 1. Git clone the Linux kernel source code
    res = sp.run(
        ["git", "clone", "https://github.com/torvalds/linux.git", "linux"],
        cwd=Path("/app"),
    )
    if res.returncode != 0:
        raise RuntimeError("Failed to clone Linux kernel source code")

    # 2. Prepare the LLVM source code
    res = sp.run(["python3", "scripts/setup_llvm.py", "/app/llvm"])
    if res.returncode != 0:
        raise RuntimeError("Failed to prepare LLVM source code")

    # 3. Copy the key file
    with open("/app/llm_keys.yaml", "w") as f:
        yaml.dump(key_config_in_docker, f)

    # 4. Generate the config file
    with open("/app/config-generate.yaml", "w") as f:
        yaml.dump(generate_config_in_docker, f)
    with open("/app/config-refine.yaml", "w") as f:
        yaml.dump(refine_config_in_docker, f)


if __name__ == "__main__":
    init_docker()
