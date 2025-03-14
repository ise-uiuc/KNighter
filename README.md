# <img src="assets/icon.png" alt="Project logo" width="40"> KNighter: Transforming Static Analysis with LLM-Synthesized Checkers

<p align="left">
    <a href="https://arxiv.org/abs/2503.09002"><img src="https://img.shields.io/badge/arXiv-2503.09002-b31b1b.svg?style=for-the-badge">
</p>

![Framework](assets/overview.svg)

## About

KNighter is a checker synthesis tool that leverages the power of LLMs to generate static analysis checkers 🦉 based on historical patch commits.

> [!IMPORTANT]
> We are keeping improving the documents and supporting more features. Please stay tuned for the updates.

**Contact:** [Chenyuan Yang](https://yangchenyuan.github.io/), [Zijie Zhao](https://zijie.cs.illinois.edu/), [Lingming Zhang](https://lingming.cs.illinois.edu).

## Environment Setup

**Step 1**

Download and build [LLVM-18.1.8](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8).

```sh
wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-18.1.8.zip
unzip llvmorg-18.1.8.zip
```

Git clone the Linux kernel source code.

```sh
git clone https://github.com/torvalds/linux.git
```

Install the following dependencies:

```sh
pip3 install -r requirements.txt
git submodule update --init --recursive
```

**Step 2**

Set up your `config.yaml`, which includes necessary config settings. Below is an example:

```yaml
result_dir: "result-checkers"
LLVM_dir: "/PATH/TO/LLVM_DIR"
checker_nums: 10
linux_dir: "/PATH/TO/LINUX_DIR"
key_file: "llm_keys.yaml"
model: "o3-mini"
```

- "result_dir": the directory to store the generated checkers.
- "LLVM_dir": the path to the LLVM environment.
- "checker_nums": the number of checkers to generate.
- "linux_dir": the path to the Linux kernel source code.
- "key_file": the key file for the models.
- "model": the model for the generated checkers.

**Step3**

Set up the LLVM environment.

```sh
python3 scripts/setup_llvm.py LLVM_PATH
```

## Pipeline Usage

Under the directory `src`, run `python3 main.py`.

```
python main.py gen --commit_file=../commits/commits-selected.txt --config_file=config.yaml
```

It in total has five models

```py
modes = {
    "gen": (gen_checker, "Generate new checkers"),
    "refine": (refine_checker, "Refine and improve checkers"),
    "scan": (scan, "Scan the kernel with valid checkers"),
    "triage": (triage_report, "Triage the report"),
    "label": (label_commits, "Label commits"),
}
```
