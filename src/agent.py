from pathlib import Path

from loguru import logger
from pydantic import BaseModel

from checker_example import choose_example
from global_config import global_config
from model import invoke_llm, invoke_llm_semgrep
from tools import error_formatting, grab_error_message

prompt_template_dir = Path(__file__).parent.parent / "prompt_template"
example_dir = prompt_template_dir / "examples"
default_checker_examples = []
semgrep_example_dir = prompt_template_dir / "semgrep_examples"
default_semgrep_examples = []

UTILITY_FUNCTION = (prompt_template_dir / "knowledge" / "utility.md").read_text()
SUGGESTIONS = (prompt_template_dir / "knowledge" / "suggestions.md").read_text()
TEMPLATE = (prompt_template_dir / "knowledge" / "template.md").read_text()


class Example(BaseModel):
    patch: str
    pattern: str
    plan: str
    checker_code: str

    @staticmethod
    def load_example_from_dir(checker_dir: str):
        checker_dir = Path(checker_dir)
        patch = (checker_dir / "patch.md").read_text()
        pattern = (checker_dir / "pattern.md").read_text()
        plan = (checker_dir / "plan.md").read_text()
        checker_code = (checker_dir / "checker.cpp").read_text()

        return Example(
            patch=patch, pattern=pattern, plan=plan, checker_code=checker_code
        )

class SemgrepExample(BaseModel):
    patch: str
    pattern: str
    plan: str
    semgrep_rule: str

    @staticmethod
    def load_example_from_dir(example_dir: str):
        example_dir = Path(example_dir)
        patch = (example_dir / "patch.md").read_text()
        pattern = (example_dir / "pattern.md").read_text() if (example_dir / "pattern.md").exists() else ""
        plan = (example_dir / "plan.md").read_text() if (example_dir / "plan.md").exists() else ""
        semgrep_rule = (example_dir / "semgrep_rule.yml").read_text() if (example_dir / "semgrep_rule.yml").exists() else ""

        return SemgrepExample(
            patch=patch, pattern=pattern, plan=plan, semgrep_rule=semgrep_rule
        )


for checker_dir in example_dir.iterdir():
    if not checker_dir.is_dir():
        continue
    default_checker_examples.append(Example.load_example_from_dir(checker_dir))

# Load semgrep examples
if semgrep_example_dir.exists():
    for semgrep_dir in semgrep_example_dir.iterdir():
        if not semgrep_dir.is_dir():
            continue
        default_semgrep_examples.append(SemgrepExample.load_example_from_dir(semgrep_dir))


def get_example_text(
    example_list,
    need_patch: bool = False,
    need_pattern: bool = False,
    need_plan: bool = False,
    need_checker: bool = False,
):
    example_text = ""
    for i, example in enumerate(example_list):
        example_text += f"## Example {i+1}\n"
        if need_patch:
            example_text += example.patch + "\n\n"
        if need_pattern:
            example_text += example.pattern + "\n\n"
        if need_plan:
            example_text += example.plan + "\n\n"
        if need_checker:
            example_text += "### Checker Code\n```cpp\n"
            example_text += example.checker_code
            example_text += "```\n\n"
    return example_text

def get_semgrep_example_text(
    example_list=None,
    need_patch: bool = True,
    need_pattern: bool = False,
    need_plan: bool = False,
    need_semgrep_rule: bool = True,
):
    """Get example text for Semgrep rules from actual example files."""
    if example_list is None:
        example_list = default_semgrep_examples
    
    if not example_list:
        # Fallback to hardcoded examples if no files found
        return """
## Example 1

### Patch
```diff
- if ($PPS[$ID]->$FIELD == false) {
-   ... 
- }
+ if ($PPS[$ID] == nullptr || $PPS[$ID]->$FIELD == false) {
+   ...
+ }
```

### Semgrep Rule
```yaml
rules:
- id: vuln-libde265-0b1752ab
  pattern: "if ($PPS[$ID]->$FIELD == false) {\n  ...\n}\n"
  pattern-not: "if ($PPS[$ID] == nullptr || $PPS[$ID]->$FIELD == false) {\n  ...\n\
    }\n"
  languages:
  - cpp
  message: 'Detected a potential null pointer dereference vulnerability. The code
    checks a field of a PPS object without first verifying that the object is not
    null. This can lead to a crash or undefined behavior. To fix this, add a null
    check before accessing the object''s fields.'
  severity: ERROR
  metadata:
    source-url: github.com/strukturag/libde265/commit/0b1752abff97cb542941d317a0d18aa50cb199b1
    category: security
    cwe:
    - CWE-476
    technology:
    - cpp
```

## Example 2

### Patch
```diff
- free(buffer);
- return;
+ free(buffer);
+ buffer = NULL;
+ return;
```

### Semgrep Rule
```yaml
rules:
  - id: use-after-free
    pattern: |
      free($VAR);
      ...
      $VAR
    pattern-not: |
      free($VAR);
      $VAR = NULL;
    languages: ["c"]
    message: "Potential use-after-free. Set pointer to NULL after freeing."
    severity: ERROR
```
"""
    
    example_text = ""
    for i, example in enumerate(example_list):
        example_text += f"## Example {i+1}\n"
        if need_patch:
            example_text += example.patch + "\n\n"
        if need_pattern and example.pattern:
            example_text += example.pattern + "\n\n"
        if need_plan and example.plan:
            example_text += example.plan + "\n\n"
        if need_semgrep_rule and example.semgrep_rule:
            example_text += "### Semgrep Rule\n```yaml\n"
            example_text += example.semgrep_rule
            example_text += "```\n\n"
    return example_text

patch2checker_template = (prompt_template_dir / "patch2checker.md").read_text()
patch2pattern_template = (
    patch2checker_template.replace("{{utility_functions}}", UTILITY_FUNCTION)
    .replace("{{suggestions}}", SUGGESTIONS)
    .replace("{{checker_template}}", TEMPLATE)
)
patch2checker_template = patch2pattern_template.replace(
    "{{examples}}",
    get_example_text(
        default_checker_examples,
        need_patch=True,
        need_pattern=False,
        need_plan=False,
        need_checker=True,
    ),
)

"""Patch to Pattern"""
patch2pattern_template = (prompt_template_dir / "patch2pattern.md").read_text()
patch2pattern_template = patch2pattern_template.replace(
    "{{examples}}",
    get_example_text(
        default_checker_examples,
        need_patch=True,
        need_pattern=True,
        need_plan=False,
        need_checker=False,
    ),
)

patch2pattern_general_template = (
    prompt_template_dir / "patch2pattern-general.md"
).read_text()
patch2pattern_general_template = patch2pattern_general_template.replace(
    "{{examples}}",
    get_example_text(
        default_checker_examples,
        need_patch=True,
        need_pattern=True,
        need_plan=False,
        need_checker=False,
    ),
)

"""Pattern to Plan"""
pattern2plan_template = (prompt_template_dir / "pattern2plan.md").read_text()
pattern2plan_template = pattern2plan_template.replace(
    "{{utility_functions}}", UTILITY_FUNCTION
)

"""Pattern to Plan without utility functions"""
pattern2plan_template_no_utility = (
    prompt_template_dir / "pattern2plan-no-utility.md"
).read_text()

"""Plan to Checker"""
plan2checker_template = (prompt_template_dir / "plan2checker.md").read_text()
plan2checker_template = (
    plan2checker_template.replace("{{utility_functions}}", UTILITY_FUNCTION)
    .replace("{{suggestions}}", SUGGESTIONS)
    .replace("{{checker_template}}", TEMPLATE)
)

plan2checker_template_no_utility = (
    prompt_template_dir / "plan2checker-no-utility.md"
).read_text()
plan2checker_template_no_utility = plan2checker_template_no_utility.replace(
    "{{suggestions}}", SUGGESTIONS
).replace("{{checker_template}}", TEMPLATE)

label_commit_template = (prompt_template_dir / "label_commit.md").read_text()


def label_commit(id: str, iter: int, commit_id, patch: str):
    logger.info("start generating label_commit prompts")
    label_commit_prompt = label_commit_template.replace("{{input_patch}}", patch)

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / f"label_commit-{commit_id}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(label_commit_prompt)
    logger.info("finish label_commit generation")

    response_store = prompt_history_dir / f"response_label_commit-{commit_id}.md"
    if response_store.exists():
        logger.info("label_commit already exists")
        response = response_store.read_text()
    else:
        response = invoke_llm(label_commit_prompt)

    if response is not None:
        response_store.write_text(response)
    else:
        response_store.write_text("SKIP")
    return response


def patch2checker(id: str, iter: int, patch: str):
    logger.info("start generating patch2checker prompts")
    patch2checker_prompt = patch2checker_template.replace("{{input_patch}}", patch)

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "patch2checker.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(patch2checker_prompt)
    logger.info("finish patch2checker generation")

    response = invoke_llm(patch2checker_prompt)
    response_store = prompt_history_dir / "response_checker.md"
    response_store.write_text(response)
    return response


def patch2pattern(id: str, iter: int, patch_info: str, use_general=False):
    logger.info("start generating patch2pattern prompts")
    if use_general:
        logger.warning("Use general template for patch2pattern")
        template = patch2pattern_general_template
    else:
        template = patch2pattern_template

    patch2pattern_prompt = template.replace("{{input_patch}}", patch_info)

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "patch2pattern.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(patch2pattern_prompt)
    logger.info("finish patch2pattern generation")

    response = invoke_llm(patch2pattern_prompt)
    response_store = prompt_history_dir / "response_patch2pattern.md"

    response_store.write_text(response)
    return response


def pattern2plan(
    id: str,
    iter: int,
    pattern: str,
    patch: str,
    no_tp_plans=None,
    no_fp_plans=None,
    no_utility=False,
    sample_examples=False,
):
    """Generate plan based on the given pattern and patch.

    Args:
        id (str): The id of the current task.
        iter (int): The iteration number.
        pattern (str): The pattern of the bug.
        patch (str): The patch of the bug.
        no_tp_plans (list, optional): Plans that cannot detect the buggy pattern. Defaults to None.
        no_fp_plans (list, optional): Plans that can label the non-buggy pattern correctly. Defaults to None.
        no_utility (bool, optional): Whether to use utility functions. Defaults to False.
        sample_examples (bool, optional): Whether to sample examples. Defaults to False.
    """
    logger.info("start generating pattern2plan prompts")
    if no_utility:
        logger.warning("No utility functions are used in pattern2plan")
        template = pattern2plan_template_no_utility
    else:
        template = pattern2plan_template

    if sample_examples:
        logger.warning("Sample examples for pattern2plan")
        example_list = choose_example(pattern, "pattern")
    else:
        example_list = default_checker_examples

    example_text = get_example_text(
        example_list,
        need_patch=False,
        need_pattern=True,
        need_plan=True,
        need_checker=False,
    )
    pattern2plan_prompt = (
        template.replace("{{input_pattern}}", pattern)
        .replace("{{input_patch}}", patch)
        .replace("{{examples}}", example_text)
    )

    feedback_plan_text = ""
    if no_tp_plans:
        no_tp_plan_text = "# Plans that cannot detect the buggy pattern\n"
        # The last three plans if there are more than 3 failed plans
        if len(no_tp_plans) > 3:
            no_tp_plans = no_tp_plans[-3:]

        for i, plan in enumerate(no_tp_plans):
            no_tp_plan_text += f"## Failed Plan {i+1}\n"
            no_tp_plan_text += plan + "\n\n"
        feedback_plan_text += no_tp_plan_text
    if no_fp_plans:
        no_fp_plan_text = "# Plans that can label the non-buggy pattern correctly\n"

        if len(no_fp_plans) > 3:
            no_fp_plans = no_fp_plans[-3:]

        for i, plan in enumerate(no_fp_plans):
            no_fp_plan_text += f"## Failed Plan {i+1}\n"
            no_fp_plan_text += plan + "\n\n"
        feedback_plan_text += no_fp_plan_text

    pattern2plan_prompt = pattern2plan_prompt.replace(
        "{{failed_plan_examples}}", feedback_plan_text
    )

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "pattern2plan.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(pattern2plan_prompt)
    logger.info("finish pattern2plan generation")

    response = invoke_llm(pattern2plan_prompt)
    response_store = prompt_history_dir / "response_plan.md"

    response_store.write_text(response)
    return response


def plan2checker(
    id: str,
    iter: int,
    pattern: str,
    refined_plan: str,
    patch: str,
    no_utility=False,
    sample_examples=False,
):
    logger.info("start generating plan2checker prompts")
    if no_utility:
        logger.warning("No utility functions are used in plan2checker")
        template = plan2checker_template_no_utility
    else:
        template = plan2checker_template

    if sample_examples:
        logger.warning("Sample examples for plan2checker")
        example_list = choose_example(refined_plan, "plan")
    else:
        example_list = default_checker_examples

    example_text = get_example_text(
        example_list,
        need_patch=False,
        need_pattern=True,
        need_plan=True,
        need_checker=True,
    )

    plan2checker_prompt = (
        template.replace("{{input_pattern}}", pattern)
        .replace("{{input_plan}}", refined_plan)
        .replace("{{input_patch}}", patch)
        .replace("{{examples}}", example_text)
    )

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "plan2checker.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(plan2checker_prompt)
    logger.info("finish plan2checker generation")

    # NOTE: Use gpt-4o for plan2checker
    response = invoke_llm(plan2checker_prompt, model="gpt-4o")
    response_store = prompt_history_dir / "response_checker.md"

    response_store.write_text(response)
    return response


def check_report(id: str, iter: int, report_id, report_md, pattern: str, patch: str):
    logger.info("start generating check_report prompts")
    check_report = (prompt_template_dir / "check_report.md").read_text()
    check_report_prompt = check_report.replace("{{input_bug_report}}", report_md)
    check_report_prompt = check_report_prompt.replace(
        "{{input_bug_pattern}}", pattern.strip("```")
    )
    check_report_prompt = check_report_prompt.replace("{{input_patch}}", patch)

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / f"check_report-{report_id}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(check_report_prompt)
    logger.info("finish check_report generation")

    response = invoke_llm(check_report_prompt, temperature=0.01)
    response_store = prompt_history_dir / f"response_check_report-{report_id}.md"

    if response is not None:
        response_store.write_text(response)
    else:
        logger.error(response)
        response = "SKIP due to empty response"
        response_store.write_text("SKIP")

    return response


def reduce_report(id: str, iter: int, report_id, report_md):
    logger.info("start generating reduce_report prompts")
    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    response_store = prompt_history_dir / f"response_reduce_report-{report_id}.md"
    if response_store.exists():
        logger.info("reduce_report already exists")
        return response_store.read_text()

    reduce_report = Path("prompt_template/reduce_report.md").read_text()
    reduce_report_prompt = reduce_report.replace("{{input_bug_report}}", report_md)

    path2store = prompt_history_dir / f"reduce_report-{report_id}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(reduce_report_prompt)
    logger.info("finish reduce_report generation")

    response = invoke_llm(reduce_report_prompt, model="gpt-4o", temperature=0.01)

    if response is not None:
        response_store.write_text(response)
    return response


def repair_FP(
    id: str,
    iter: int,
    commit_id: str,
    pattern: str,
    report,
    checker_code,
    analysis,
    patch,
):
    logger.info("start generating repair_FP prompts")
    repair_FP = (prompt_template_dir / "repair_FP.md").read_text()
    repair_FP_prompt = repair_FP.replace("{{input_checker}}", checker_code)
    repair_FP_prompt = repair_FP_prompt.replace(
        "{{input_bug_pattern}}", pattern.strip("```")
    )
    repair_FP_prompt = repair_FP_prompt.replace("{{input_bug_report}}", report)
    repair_FP_prompt = repair_FP_prompt.replace("{{input_analysis}}", analysis)
    repair_FP_prompt = repair_FP_prompt.replace("{{input_patch}}", patch)

    repair_FP_prompt = repair_FP_prompt.replace(
        "{{utility_functions}}", UTILITY_FUNCTION
    )

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / f"repair_FP-{commit_id}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(repair_FP_prompt)
    logger.info("finish repair_FP generation")

    response = invoke_llm(repair_FP_prompt, temperature=0.01)
    response_store = prompt_history_dir / f"response_repair_FP-{commit_id}.md"

    response_store.write_text(response)
    return response


def repair_syntax(id: str, iter: int, times, checker_code, error_content):
    logger.info("start generating repair_syntax prompts")
    template = (prompt_template_dir / "repair.md").read_text()

    error_list = grab_error_message(error_content)
    error_list_md = error_formatting(error_list)
    prompt = template.replace("{checkercode}", checker_code).replace(
        "{errors}", error_list_md
    )

    prompt_history_dir = (
        Path(global_config.result_dir) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / f"repair_syntax-{times}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(prompt)
    logger.info("finish repair_syntax generation")

    response = invoke_llm(prompt)
    if response is None:
        logger.error("Empty response")
        response = "SKIP"

    response_store = prompt_history_dir / f"response_repair_syntax-{times}.md"
    response_store.write_text(response)
    return response

"""Patch to Semgrep Rule"""
patch2semgrep_template = (prompt_template_dir / "patch2semgrep.md").read_text()

"""Pattern to Semgrep Plan"""
pattern2semplan_template = (prompt_template_dir / "pattern2semplan.md").read_text()

"""Plan to Semgrep Rule"""
plan2semgrep_template = (prompt_template_dir / "plan2semgrep.md").read_text()

"""Repair Semgrep Rule"""
repair_semgrep_template = (prompt_template_dir / "repair_semgrep.md").read_text()


def patch2semgrep(id: str, iter: int, patch: str):
    """Generate Semgrep rule directly from patch."""
    logger.info("start generating patch2semgrep prompts")
    
    # Use semgrep examples if available
    example_text = get_semgrep_example_text()
    
    patch2semgrep_prompt = patch2semgrep_template.replace("{{input_patch}}", patch)
    patch2semgrep_prompt = patch2semgrep_prompt.replace("{{examples}}", example_text)

    prompt_history_dir = (
        Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "patch2semgrep.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(patch2semgrep_prompt)
    logger.info("finish patch2semgrep generation")

    response = invoke_llm(patch2semgrep_prompt)
    response_store = prompt_history_dir / "response_semgrep.md"
    response_store.write_text(response)
    return response


def plan2semgrep(
    id: str,
    iter: int,
    pattern: str,
    plan: str,
    patch: str,
    no_utility=False,
    sample_examples=False,
):
    """Generate Semgrep rule from plan."""
    logger.info("start generating plan2semgrep prompts")
    
    # Use semgrep examples if available
    if sample_examples:
        logger.warning("Sample examples for plan2semgrep")
        # TODO: Implement sampling for semgrep examples
        example_text = get_semgrep_example_text()
    else:
        example_text = get_semgrep_example_text()
    
    plan2semgrep_prompt = (
        plan2semgrep_template.replace("{{input_pattern}}", pattern)
        .replace("{{input_plan}}", plan)
        .replace("{{input_patch}}", patch)
        .replace("{{examples}}", example_text)
    )

    prompt_history_dir = (
        Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "plan2semgrep.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(plan2semgrep_prompt)
    logger.info("finish plan2semgrep generation")

    response = invoke_llm_semgrep(plan2semgrep_prompt)
    response_store = prompt_history_dir / "response_semgrep.md"
    response_store.write_text(response)
    return response


def repair_semgrep_syntax(id: str, repair_name: str, times: int, semgrep_rule: str, error_content: str):
    """Repair Semgrep rule syntax errors."""
    logger.info("start generating repair_semgrep_syntax prompts")
    
    prompt = (
        repair_semgrep_template.replace("{{semgrep_rule}}", semgrep_rule)
        .replace("{{error_messages}}", error_content)
    )

    prompt_history_dir = (
        Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id / "prompt_history" / repair_name
    )
    path2store = prompt_history_dir / f"repair_semgrep_syntax-{times}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(prompt)
    logger.info("finish repair_semgrep_syntax generation")

    response = invoke_llm(prompt)
    if response is None:
        logger.error("Empty response")
        response = "SKIP"

    response_store = prompt_history_dir / f"response_repair_semgrep_syntax-{times}.md"
    response_store.write_text(response)
    return response


def pattern2semplan(
    id: str,
    iter: int,
    pattern: str,
    patch: str,
    no_tp_plans=None,
    no_fp_plans=None,
    sample_examples=False,
):
    """Generate Semgrep plan based on the given pattern and patch.

    Args:
        id (str): The id of the current task.
        iter (int): The iteration number.
        pattern (str): The pattern of the bug.
        patch (str): The patch of the bug.
        no_tp_plans (list, optional): Plans that cannot detect the buggy pattern. Defaults to None.
        no_fp_plans (list, optional): Plans that can label the non-buggy pattern correctly. Defaults to None.
        sample_examples (bool, optional): Whether to sample examples. Defaults to False.
    """
    logger.info("start generating pattern2semplan prompts")
    
    template = pattern2semplan_template

    if sample_examples:
        logger.warning("Sample examples for pattern2semplan")
        # TODO: Implement sampling for semgrep examples
        example_text = get_semgrep_example_text(need_pattern=True, need_plan=True, need_semgrep_rule=False)
    else:
        example_text = get_semgrep_example_text(need_pattern=True, need_plan=True, need_semgrep_rule=False)
    
    pattern2semplan_prompt = (
        template.replace("{{input_pattern}}", pattern)
        .replace("{{input_patch}}", patch)
        .replace("{{examples}}", example_text)
    )

    feedback_plan_text = ""
    if no_tp_plans:
        no_tp_plan_text = "# Plans that cannot detect the buggy pattern\n"
        # The last three plans if there are more than 3 failed plans
        if len(no_tp_plans) > 3:
            no_tp_plans = no_tp_plans[-3:]

        for i, plan in enumerate(no_tp_plans):
            no_tp_plan_text += f"## Failed Plan {i+1}\n"
            no_tp_plan_text += plan + "\n\n"
        feedback_plan_text += no_tp_plan_text
    if no_fp_plans:
        no_fp_plan_text = "# Plans that can label the non-buggy pattern correctly\n"

        if len(no_fp_plans) > 3:
            no_fp_plans = no_fp_plans[-3:]

        for i, plan in enumerate(no_fp_plans):
            no_fp_plan_text += f"## Failed Plan {i+1}\n"
            no_fp_plan_text += plan + "\n\n"
        feedback_plan_text += no_fp_plan_text

    pattern2semplan_prompt = pattern2semplan_prompt.replace(
        "{{failed_plan_examples}}", feedback_plan_text
    )

    prompt_history_dir = (
        Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id / "prompt_history" / str(iter)
    )
    path2store = prompt_history_dir / "pattern2semplan.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(pattern2semplan_prompt)
    logger.info("finish pattern2semplan generation")

    response = invoke_llm(pattern2semplan_prompt)
    response_store = prompt_history_dir / "response_semplan.md"

    response_store.write_text(response)
    return response