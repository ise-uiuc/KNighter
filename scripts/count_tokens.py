"""
Example usage:
    python count_tokens.py /path/to/result/dir
    
This script counts input and output tokens in result files.
"""

from pathlib import Path
import tiktoken
import fire

def count_input_tokens(result_dir: str) -> int:
    result_dir = Path(result_dir)
    files = []
    for log_file in result_dir.rglob("prompt_history/*/*.md"):
        if not log_file.name.startswith("response_"):
            files.append(log_file)
    print(f"Found {len(files)} input files.")
    return count_output_tokens(files)

def get_output_files(result_dir: str):
    """Collect all output files including responses and repairs."""
    result_dir = Path(result_dir)
    output_files = list(result_dir.rglob("response_*.md"))
    # output_files.extend(result_dir.rglob("intermediate-*/checker-*.cpp"))
    return output_files

def count_output_tokens(files, model: str = "gpt-4o") -> int:
    """Count tokens in output files using specified model's tokenizer."""
    encoding = tiktoken.encoding_for_model(model)
    return sum(len(encoding.encode(file.read_text())) for file in files)

def main(result_dir: str, model: str = "gpt-4o"):
    """
    Count input and output tokens in the specified result directory.
    
    Args:
        result_dir: Directory containing the result files
        model: Model name for tokenizer (default: gpt-4)
    """
    input_tokens = count_input_tokens(result_dir)
    print(f"Total number of input tokens: {input_tokens}")
    
    output_files = get_output_files(result_dir)
    print(f"Number of output files: {len(output_files)}")
    
    output_tokens = count_output_tokens(output_files, model)
    print(f"Total number of output tokens: {output_tokens}")

if __name__ == "__main__":
    fire.Fire(main)
