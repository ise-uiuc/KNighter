# This script is from https://github.com/harperchen/SEAL/blob/main/helper_scripts/00_patch_collector.py.
# It is used to collect patches from the Linux kernel repository.

import re
import sys
import chardet

from pip._internal.vcs.git import Git
from unidiff import PatchSet

import pandas as pd
from git import Repo
from pydriller import *
from rich.progress import track

commit_pattern = re.compile(r'^(commit\s[a-f0-9]{40})\n(Author:\s.+)\n(Date:\s+.*?)(?=\n\n)(.+?)(?:(?=\n\ndiff)|$)',
                            re.DOTALL)
bug_fix_keywords = ["fix", "bug", "issue", "error", "crash", "hang",
                    "fault", "fail", "check", "mistake",
                    "incorrect", "defect", "leak"]

not_bug_fix_keywords = ["fix compilation", "fix compile", "add support", "support",
                        "build error", "spell", "typo", "link error", "no functional change"]

release_date_v4_19 = 'Oct 22 2018'

num_code_changes = 0
num_for_4_19 = 0
num_drivers = 0
num_reverted = 0
num_cc_stable = 0
num_dynamic = 0
num_static = 0
num_bug = 0
num_bug_fix = 0
num_bug_type = {'Use-After-Free': 0, 'Resource-Leak': 0, 'Null-Ptr-Deref': 0,
                'UnInitialization': 0, 'Out-of-bound': 0, 'Divide-by-zero': 0,
                'Double-free': 0, 'Taint-Style': 0, 'Wrong-Error-Code': 0,
                'Error-Handling': 0, "Memory-Leak": 0, 'Lock-Misuse': 0,
                'Integer-Flow': 0, "Memory-Corruption": 0, 'Signedness-Bug': 0}

class PatchCollector:
    def __init__(self, repo_name) -> None:
        self.repo_name = repo_name
        self.source_dir = "/scratch/chenyuan-data/linux"  # in commit v6.2
        self.repo = Repo(self.source_dir)
        self.repo1 = Git(self.source_dir)
        self.commit_url = "https://github.com/torvalds/linux/commit/"

    def get_patches(self, patch_file_path):
        branch = "v6.13"
        print("Collecting patches in ", self.repo_name, branch)
        # 2019/02/19-2023/02/19 commits in v6.2
        idlist = list(
            self.repo.iter_commits(
                branch, max_count=200000, no_merges=True,
            )
        )
        df = pd.DataFrame()
        print(f"Processing all the patches to find suspects, total patch number is: {len(idlist)}")
        for i in track(idlist):
            patch = f"{self.commit_url}{i.hexsha[:12]}"
            if self.check_is_related_to_bug(i.hexsha[:12]):

                commit = self.repo1.get_commit(i.hexsha)
                subject, message, _, _ = self.parse_commit_log(commit.msg)

                to_be_checked = message.lower() + ' ' + subject.lower() + ' '
                bug_type = self.set_bug_type(to_be_checked)

                item = {"hexsha": i.hexsha[:12], "patch": patch, "summary": i.summary, "author": i.author.name, "bug_type": bug_type,}

                df_new_row = pd.DataFrame([item])
                df = pd.concat([df, df_new_row], ignore_index=True)
                df.to_csv(patch_file_path, index=False)
        print(f"Done, the collected patch is {len(df)}, save to file " + patch_file_path)
        

    def check_is_related_to_bug(self, hexsha):
        return bool(self.check_if_interest(hexsha)
                    and self.check_patch_description(hexsha)
                    and self.check_code_changes(hexsha))

    def check_if_interest(self, hexsha):
        commit = self.repo1.get_commit(hexsha)
        for f in commit.modified_files:
            if f.new_path and not f.new_path.endswith('.c') \
                    and not f.new_path.endswith('.h'):
                return False
            if f.new_path \
                    and not f.new_path.startswith("drivers/") \
                    and not f.new_path.startswith("sound/") \
                    and not f.new_path.startswith("arch/") \
                    and not f.new_path.startswith("samples/") \
                    and not f.new_path.startswith("include/") \
                    and not f.new_path.startswith("net/") \
                    and not f.new_path.startswith("fs/"):
                return False
        return True

    def check_patch_description(self, hexsha):
        commit = self.repo1.get_commit(hexsha)
        subject, message, sign_off, is_revert = self.parse_commit_log(commit.msg)
        if is_revert:
            return False
        to_be_checked = message + ' ' + subject + ' '
        to_be_checked = to_be_checked.lower()
        if not self.check_if_bug_fix(to_be_checked):
            return False
        if self.check_if_dynamic(to_be_checked):
            return True
        if self.check_if_static(to_be_checked):
            return True
        if self.set_bug_type(to_be_checked) == "UnKnown":
            return False
        return True

    def check_code_changes(self, hexsha):
        commit = self.repo1.get_commit(hexsha)
        if commit.files > 5 or commit.insertions > 30 or commit.deletions > 30:
            return False

        # func-level check: no modification for func or too many funcs
        modified_func = []
        for f in commit.modified_files:
            modified_func.extend(method.name for method in f.changed_methods)
        return 1 <= len(modified_func) <= 5
    
    @staticmethod
    def set_bug_type(to_be_checked):
        if 'sanity' in to_be_checked or \
                'controlled by user' in to_be_checked or \
                'malicious device' in to_be_checked or \
                'malicious user' in to_be_checked or \
                'user-controlled' in to_be_checked or \
                'malfunctioning' in to_be_checked or \
                'malformed' in to_be_checked or \
                'from user' in to_be_checked or \
                'user data' in to_be_checked or \
                'user input' in to_be_checked:
            return "Taint-Style"
        elif 'use after free' in to_be_checked or \
                'use-after-free' in to_be_checked or \
                'uaf' in to_be_checked:
            return "Use-After-Free"
        elif 'resource leak' in to_be_checked or \
            'refcount leak' in to_be_checked:
            return "Resource-Leak"
        elif re.search(r" (lock|unlock|deadlock) ", to_be_checked):
            return 'Lock-Misuse'
        elif 'sign extension' in to_be_checked or \
                'sign-extension' in to_be_checked or \
                'signedness bug' in to_be_checked or \
                'unsigned comparison' in to_be_checked:
            return 'Signedness-Bug'
        elif 'null ptr' in to_be_checked or \
                'pointer dereference' in to_be_checked or \
                'null pointer dereference' in to_be_checked or \
                'null dereference' in to_be_checked or \
                'npd' in to_be_checked or \
                'null pointer' in to_be_checked or \
                'null-ptr-deref' in to_be_checked or \
                'null-deref' in to_be_checked or \
                'null check' in to_be_checked or \
                ' gpf ' in to_be_checked or \
                'protection fault' in to_be_checked or \
                'null-pointer' in to_be_checked or \
                'dereferenced' in to_be_checked or \
                'handle kernel paging request' in to_be_checked:
            return 'Null-Ptr-Deref'
        elif "uninitialize" in to_be_checked or \
                'uninit-value' in to_be_checked or \
                'ununit-value' in to_be_checked or \
                'uninit value' in to_be_checked or \
                'initialized' in to_be_checked:
            return 'UnInitialization'
        elif 'integer overflow' in to_be_checked or \
                'integer underflow' in to_be_checked or \
                'index underflow' in to_be_checked or \
                'shift_out_of_bounds' in to_be_checked:
            return 'Integer-Flow'
        elif 'out of bound' in to_be_checked or \
                'oob' in to_be_checked or \
                'out-of-bound' in to_be_checked or \
                'overflow' in to_be_checked or \
                'handle page fault' in to_be_checked:
            return 'Out-of-bound'
        elif 'divide by zero' in to_be_checked or \
                'zero divide' in to_be_checked or \
                ('divide' in to_be_checked and 'zero' in to_be_checked) or \
                ('division' in to_be_checked and 'zero' in to_be_checked) \
                or 'divide error' in to_be_checked \
                or 'zero out' in to_be_checked:
            return 'Divide-by-zero'
        elif 'double free' in to_be_checked or \
                'double-free' in to_be_checked:
            return "Double-free"
        elif 'mem leak' in to_be_checked or \
                'memleak' in to_be_checked or \
                'memory leak' in to_be_checked or \
                'ref count' in to_be_checked or \
                'refcount' in to_be_checked or \
                'refcnt leak' in to_be_checked or \
                'unbalanced' in to_be_checked or \
                'imbalance' in to_be_checked or \
                'leak' in to_be_checked or \
                re.search('.*fix missing.*\(\)', to_be_checked) or \
                re.search('.*add missing.*\(\)', to_be_checked):
            return "Memory-Leak"
        elif 'memory corruption' in to_be_checked:
            return "Memory-Corruption"
        elif 'error code' in to_be_checked or \
                'wrong return value' in to_be_checked or \
                'error return code' in to_be_checked or \
                'incorrect return value' in to_be_checked or \
                'fix return value' in to_be_checked or \
                'return value check' in to_be_checked or \
                'fix error code' in to_be_checked:
            return "Wrong-Error-Code"
        elif 'unchecked return' in to_be_checked or \
                'error handle' in to_be_checked or \
                'error handl' in to_be_checked or \
                'check return' in to_be_checked or \
                'check for return value' in to_be_checked or \
                'check for error' in to_be_checked or \
                'error handling' in to_be_checked or \
                'error path' in to_be_checked or \
                'error check' in to_be_checked or \
                'error return' in to_be_checked or \
                'return value' in to_be_checked or \
                'handle error' in to_be_checked:
            return "Error-Handling"
        else:
            return "UnKnown"
        
    @staticmethod
    def parse_commit_log(commit_log: str):
        commit_log = commit_log.lower()
        signature_pattern = re.compile(
            r'^(?:signed-off-by:|reported-by:|tested-by:|reviewed-by:|cc:|fixes:|'
            r'acked-by:|change-Id:|link:|suggested-by:|requested-by:|reported by:|merged from|reported-and-tested-by:).*',
            re.MULTILINE | re.IGNORECASE)
        signed_off_by_matches = re.findall(signature_pattern, commit_log)

        if signed_off_by_matches is None or len(signed_off_by_matches) == 0:
            if 'Signed-off-by:'.lower() in commit_log.lower() or \
                    'Reported-by:'.lower() in commit_log.lower() or \
                    'Tested-by:'.lower() in commit_log.lower() or \
                    'Reviewed-by:'.lower() in commit_log.lower() or \
                    'Cc:'.lower() in commit_log.lower() or \
                    'Acked-by:'.lower() in commit_log.lower() or \
                    'Change-Id:'.lower() in commit_log.lower() or \
                    "Fixes:".lower() in commit_log.lower():
                return "", ""
            else:
                # print("[{}/{}] Signed off not match: {}\n{}".format(i, num_patches, filepath, message))
                signed_off_by_start = commit_log.find('diff --git')
        else:
            signed_off_by_start = commit_log.find(signed_off_by_matches[0])

        if 'diff --git' in commit_log and signed_off_by_start >= commit_log.find('diff --git'):
            signed_off_by_start = commit_log.find('diff --git')

        commit_info = commit_log[:signed_off_by_start].strip()
        message_items = commit_info.split("\n\n")

        message_subject = message_items[0] if len(message_items) >= 1 else ""
        message_body = commit_info if len(message_items) == 1 else "\n\n".join(message_items[1:])
        message_body = re.sub(r'[0-9a-fA-F]+\s\(\".*?\"\)', '', message_body)

        is_revert = False
        if 'revert'.lower() in message_subject.lower():
            is_revert = True

        return message_subject, message_body.replace('\n', ' '), "\n".join(signed_off_by_matches), is_revert



    
    @staticmethod
    def check_if_dynamic(to_be_checked: str):
        if 'kasan' in to_be_checked:
            return True
        if 'fuzzing' in to_be_checked:
            return True
        if 'fuzzer' in to_be_checked:
            return True
        if 'syzkaller' in to_be_checked:
            return True
        if 'kmemleak' in to_be_checked:
            return True
        if 'kcsan' in to_be_checked:
            return True
        if 'kmsan' in to_be_checked:
            return True
        if 'ubsan' in to_be_checked:
            return True
        if 'syzbot' in to_be_checked:
            return True

        return False

    @staticmethod
    def check_if_static(to_be_checked: str):
        if ' smatch' in to_be_checked:
            return True
        if 'static analysis' in to_be_checked:
            return True
        if 'coverity' in to_be_checked:
            return True
        # if 'coccinelle' in to_be_checked:
        #     return True

        return False

    @staticmethod
    def check_if_bug_fix(to_be_checked: str):
        is_error = False
        for error in bug_fix_keywords:
            if error in to_be_checked:
                is_error = True

        is_support = False
        for support in not_bug_fix_keywords:
            if support in to_be_checked:
                is_support = True
        return is_error and not is_support

    @staticmethod
    def check_if_cc_stable(commit_log: str):
        if 'stable' in commit_log:
            if 'stable@vger.kernel.org' in commit_log:
                return True
            elif 'stable@kernel.org' in commit_log:
                return True
            else:
                return False
        return False

    @staticmethod
    def check_if_code_changes(file_path: str):
        global modified_func_tot
        is_c_h_file = False
        with open(file_path, mode='rb') as file:
            raw_data = file.read()
            encoding = chardet.detect(raw_data)['encoding']

        with open(file_path, mode='r', encoding=encoding, errors="ignore") as file:
            patch = PatchSet(file)

            for patched_file in patch.modified_files:
                if patched_file.path.endswith('.c') or patched_file.path.endswith('.h'):
                    is_c_h_file = True

        return is_c_h_file

if __name__ == '__main__':
    if sys.argv[1] == 'collect':
        patch_file_path = sys.argv[2]
        collecter = PatchCollector("kernel")
        collecter.get_patches(patch_file_path)
        