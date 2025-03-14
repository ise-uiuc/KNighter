import re
from pathlib import Path

from loguru import logger
from pydantic import BaseModel

from model import invoke_llm

result_dir = Path("tmp-result")


class Example(BaseModel):
    patch: str
    pattern: str
    plan: str
    checker_code: str


prompt_template_dir = Path(__file__).parent.parent / "prompt_template"

CHECKER_EXAMPLES = []
example_dir = prompt_template_dir / "examples"
for checker_dir in example_dir.iterdir():
    if not checker_dir.is_dir():
        continue
    patch = (checker_dir / "patch.md").read_text()
    pattern = (checker_dir / "pattern.md").read_text()
    plan = (checker_dir / "plan.md").read_text()
    checker_code = (checker_dir / "checker.cpp").read_text()

    CHECKER_EXAMPLES.append(
        Example(patch=patch, pattern=pattern, plan=plan, checker_code=checker_code)
    )

UTILITY_FUNCTION = (prompt_template_dir / "knowledge" / "utility.md").read_text()
SUGGESTIONS = (prompt_template_dir / "knowledge" / "suggestions.md").read_text()
TEMPLATE = (prompt_template_dir / "knowledge" / "template.md").read_text()


def get_example_text(
    need_patch: bool, need_pattern: bool, need_plan: bool, need_checker: bool
):
    example_text = ""
    for i, example in enumerate(CHECKER_EXAMPLES):
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


patch2checker_template = (prompt_template_dir / "patch2checker.md").read_text()
patch2pattern_template = (
    patch2checker_template.replace("{{utility_functions}}", UTILITY_FUNCTION)
    .replace("{{suggestions}}", SUGGESTIONS)
    .replace("{{checker_template}}", TEMPLATE)
)
patch2checker_template = patch2pattern_template.replace(
    "{{examples}}",
    get_example_text(
        need_patch=True, need_pattern=False, need_plan=False, need_checker=True
    ),
)

patch2pattern_template = (prompt_template_dir / "patch2pattern.md").read_text()
patch2pattern_template = patch2pattern_template.replace(
    "{{examples}}",
    get_example_text(
        need_patch=True, need_pattern=True, need_plan=False, need_checker=False
    ),
)

patch2pattern_general_template = (
    prompt_template_dir / "patch2pattern-general.md"
).read_text()
patch2pattern_general_template = patch2pattern_general_template.replace(
    "{{examples}}",
    get_example_text(
        need_patch=True, need_pattern=True, need_plan=False, need_checker=False
    ),
)

pattern2plan_template = (prompt_template_dir / "pattern2plan.md").read_text()
pattern2plan_template = pattern2plan_template.replace(
    "{{utility_functions}}", UTILITY_FUNCTION
)
pattern2plan_template = pattern2plan_template.replace(
    "{{examples}}",
    get_example_text(
        need_patch=False, need_pattern=True, need_plan=True, need_checker=False
    ),
)

pattern2plan_template_no_utility = (
    prompt_template_dir / "pattern2plan-no-utility.md"
).read_text()
pattern2plan_template_no_utility = pattern2plan_template_no_utility.replace(
    "{{examples}}",
    get_example_text(
        need_patch=False, need_pattern=True, need_plan=True, need_checker=False
    ),
)

plan2checker_template = (prompt_template_dir / "plan2checker.md").read_text()
plan2checker_template = (
    plan2checker_template.replace("{{utility_functions}}", UTILITY_FUNCTION)
    .replace("{{suggestions}}", SUGGESTIONS)
    .replace("{{checker_template}}", TEMPLATE)
)
plan2checker_template = plan2checker_template.replace(
    "{{examples}}",
    get_example_text(
        need_patch=False, need_pattern=True, need_plan=True, need_checker=True
    ),
)

plan2checker_template_no_utility = (
    prompt_template_dir / "plan2checker-no-utility.md"
).read_text()
plan2checker_template_no_utility = plan2checker_template_no_utility.replace(
    "{{examples}}",
    get_example_text(
        need_patch=False, need_pattern=True, need_plan=True, need_checker=True
    ),
)
plan2checker_template_no_utility = plan2checker_template_no_utility.replace(
    "{{suggestions}}", SUGGESTIONS
).replace("{{checker_template}}", TEMPLATE)

label_commit_template = (prompt_template_dir / "label_commit.md").read_text()


def label_commit(id: str, iter: int, commit_id, patch: str):
    logger.info("start generating label_commit prompts")
    label_commit_prompt = label_commit_template.replace("{{input_patch}}", patch)

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
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

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
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

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
    path2store = prompt_history_dir / "patch2pattern.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(patch2pattern_prompt)
    logger.info("finish patch2pattern generation")

    response = invoke_llm(patch2pattern_prompt)
    response_store = prompt_history_dir / "response_patch2pattern.md"

    response_store.write_text(response)
    return response


def patch2demo(id: str, iter: int, patch_info: str):
    logger.info(f"start generating demo{iter}.")
    patch2demo = Path("prompt/patch2demo.md").read_text()
    patch2demo_prompt = patch2demo.replace("# {patchinfo(replace)}", patch_info)

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
    path2store = prompt_history_dir / "patch2demo.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    if iter == 0:
        path2store.write_text(patch2demo_prompt)

    response = invoke_llm(patch2demo_prompt)
    pattern = r"```c\n([\s\S]*?)\n```"
    matches = re.findall(pattern, response)

    base_dir = Path(result_dir) / id
    demo_buggy_dir = Path(base_dir) / "demos" / "buggy"
    demo_nonbuggy_dir = Path(base_dir) / "demos" / "nonbuggy"
    demo_buggy_filepath = demo_buggy_dir / f"demo{iter}.c"
    demo_nonbuggy_filepath = demo_nonbuggy_dir / f"demo{iter}.c"

    demo_buggy_dir.mkdir(parents=True, exist_ok=True)
    demo_nonbuggy_dir.mkdir(parents=True, exist_ok=True)

    demo_buggy_filepath.write_text(matches[0])
    demo_nonbuggy_filepath.write_text(matches[1])


def pattern2plan(
    id: str,
    iter: int,
    pattern: str,
    patch: str,
    no_tp_plans=None,
    no_fp_plans=None,
    no_utility=False,
):
    logger.info("start generating pattern2plan prompts")
    if no_utility:
        logger.warning("No utility functions are used in pattern2plan")
        template = pattern2plan_template_no_utility
    else:
        template = pattern2plan_template

    pattern2plan_prompt = template.replace("{{input_pattern}}", pattern).replace(
        "{{input_patch}}", patch
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

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
    path2store = prompt_history_dir / "pattern2plan.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(pattern2plan_prompt)
    logger.info("finish pattern2plan generation")

    response = invoke_llm(pattern2plan_prompt)
    response_store = prompt_history_dir / "response_plan.md"

    response_store.write_text(response)
    return response


def refine_plan(id: str, iter: int, pattern: str, plan: str):
    logger.info("start generating refine_plan prompts")
    plan_refine = Path("prompt/plan_refine.md").read_text()
    plan_refine_prompt = plan_refine.replace(
        "# {bugpattern(replace)}", pattern.strip("```")
    )
    plan_refine_prompt = plan_refine_prompt.replace(
        "# {originalplan(replace)}", plan.strip("```")
    )

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
    path2store = prompt_history_dir / "plan_refine.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(plan_refine_prompt)
    logger.info("finish refine_plan generation")
    response = invoke_llm(plan_refine_prompt)
    response_store = prompt_history_dir / "response_refinedplan.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    response_store.write_text(response)
    return response


def plan2checker(
    id: str, iter: int, pattern: str, refined_plan: str, patch: str, no_utility=False
):
    logger.info("start generating plan2checker prompts")
    if no_utility:
        logger.warning("No utility functions are used in plan2checker")
        template = plan2checker_template_no_utility
    else:
        template = plan2checker_template

    plan2checker_prompt = (
        template.replace("{{input_pattern}}", pattern)
        .replace("{{input_plan}}", refined_plan)
        .replace("{{input_patch}}", patch)
    )

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
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

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
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
    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
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
    id: str, iter: int, commit_id, pattern: str, report, checker_code, analysis, patch
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

    prompt_history_dir = Path(result_dir) / id / "prompt_history" / str(iter)
    path2store = prompt_history_dir / f"repair_FP-{commit_id}.md"
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    path2store.write_text(repair_FP_prompt)
    logger.info("finish repair_FP generation")

    response = invoke_llm(repair_FP_prompt, temperature=0.01)
    response_store = prompt_history_dir / f"response_repair_FP-{commit_id}.md"

    response_store.write_text(response)
    return response
