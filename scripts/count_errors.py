# Count the number and types of errors
# Example usage:
# python scripts/count_errors.py --input_file result/input.log --output_file output.csv

import fire
from pathlib import Path

def count_errors(line, output_file):
    commit = line.split()[0]
    type = line.split()[1]
    ranking_text = " ".join(line.split()[2:])
    
    ranking_list = eval(ranking_text)
    any_valid = any([ranking[1] > 0 and ranking[2] > 0 for ranking in ranking_list])

    num_compilation_failures = 0
    num_runtime_errors = 0
    num_semantic_errors = 0
    num_all_bug = 0
    num_all_not_bug = 0
    for ranking in ranking_list:
        if ranking[1] == -10:
            num_compilation_failures += 1
        elif ranking[1] == -2:
            num_runtime_errors += 1
        elif not (ranking[1] > 0 and ranking[2] > 0):
            num_semantic_errors += 1
            if ranking[1] == 0:
                num_all_not_bug += 1
            else:
                num_all_bug += 1

    with open(output_file, 'a') as f:
        f.write(f"{commit},{type},{any_valid},{num_compilation_failures},{num_runtime_errors},{num_semantic_errors},{num_all_bug},{num_all_not_bug}\n")


def count_errors_from_file(input_file, output_file):
    input_file = Path(input_file)
    output_file = Path(output_file)
    output_file.write_text("commit,type,any_valid,num_compilation_failures,num_runtime_errors,num_semantic_errors,num_all_bug,num_all_not_bug\n")
    for line in input_file.read_text().splitlines():
        count_errors(line, output_file)

if __name__ == "__main__":
    fire.Fire(count_errors_from_file)
