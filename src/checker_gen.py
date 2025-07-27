import time
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import json

from agent import patch2checker, patch2pattern, pattern2plan, plan2checker
from checker_data import CheckerData
from checker_example import init_example
from checker_repair import repair_checker
from global_config import global_config, logger
from tools import extract_checker_code


@dataclass
class GenerationProgress:
    """Track progress of checker generation."""
    total_steps: int = 6
    current_step: int = 0
    step_names: List[str] = field(default_factory=lambda: [
        "🔍 Pattern Extraction",
        "📋 Plan Generation", 
        "💻 Code Generation",
        "🔧 Syntax Repair",
        "✅ Validation",
        "📊 Summary"
    ])
    start_time: datetime = field(default_factory=datetime.now)
    step_times: Dict[str, float] = field(default_factory=dict)
    
    def start_step(self, step_name: str = None):
        """Start a new step."""
        if step_name is None:
            step_name = self.step_names[self.current_step]
        
        self.current_step += 1
        progress = (self.current_step / self.total_steps) * 100
        
        logger.info(f"[{progress:5.1f}%] {step_name}")
        print(f"⏳ [{progress:5.1f}%] {step_name}...")
        
        self.step_times[step_name] = time.time()
        return step_name
    
    def complete_step(self, step_name: str, details: str = ""):
        """Complete the current step."""
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
            self.step_times[step_name] = duration
        else:
            duration = 0
            
        print(f"✅ {step_name} ({duration:.1f}s)")
        if details:
            print(f"   └── {details}")
        logger.info(f"Completed: {step_name} in {duration:.1f}s - {details}")
    
    def fail_step(self, step_name: str, error: str):
        """Mark step as failed."""
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
        else:
            duration = 0
            
        print(f"❌ {step_name} ({duration:.1f}s)")
        print(f"   └── Error: {error}")
        logger.error(f"Failed: {step_name} in {duration:.1f}s - {error}")
    
    def get_total_time(self) -> float:
        """Get total elapsed time."""
        return (datetime.now() - self.start_time).total_seconds()


@dataclass
class GenerationSummary:
    """Summary of checker generation results."""
    commit_id: str
    commit_type: str
    total_checkers: int
    successful_checkers: int
    perfect_checkers: int
    best_tp: int
    best_tn: int
    total_time: float
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "commit_type": self.commit_type,
            "total_checkers": self.total_checkers,
            "successful_checkers": self.successful_checkers,
            "perfect_checkers": self.perfect_checkers,
            "best_tp": self.best_tp,
            "best_tn": self.best_tn,
            "total_time": self.total_time,
            "errors": self.errors,
            "success_rate": self.successful_checkers / max(self.total_checkers, 1),
            "timestamp": datetime.now().isoformat()
        }
    
    def print_summary(self):
        """Print a formatted summary."""
        print("\n" + "="*60)
        print(f"🎯 GENERATION SUMMARY")
        print("="*60)
        print(f"📋 Commit: {self.commit_id} ({self.commit_type})")
        print(f"⏱️  Total Time: {self.total_time:.1f}s")
        print(f"🔢 Checkers Generated: {self.total_checkers}")
        print(f"✅ Successful: {self.successful_checkers}/{self.total_checkers}")
        print(f"🎉 Perfect: {self.perfect_checkers}")
        print(f"🏆 Best Scores: TP={self.best_tp}, TN={self.best_tn}")
        
        if self.errors:
            print(f"⚠️  Errors: {len(self.errors)}")
            for i, error in enumerate(self.errors[:3], 1):
                print(f"   {i}. {error}")
            if len(self.errors) > 3:
                print(f"   ... and {len(self.errors) - 3} more")
        
        success_rate = self.successful_checkers / max(self.total_checkers, 1)
        if success_rate >= 0.8:
            print("🌟 Excellent generation rate!")
        elif success_rate >= 0.5:
            print("👍 Good generation rate")
        else:
            print("⚠️  Low generation rate - consider reviewing parameters")
        print("="*60)


def gen_checker(
    commit_file="commits.txt",
    result_file=None,
    use_multi=True,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    """Generate checkers for multiple commits with improved output format."""
    
    print("🚀 Starting Checker Generation")
    print(f"📁 Config: multi={use_multi}, general={use_general}, utility={not no_utility}")
    logger.info(f"Starting batch generation with multi={use_multi}")

    content = Path(commit_file).read_text()
    result_dir = Path(global_config.result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)

    result_content = ""
    if result_file:
        result_content = Path(result_file).read_text()

    # Init example checkers if needed
    if sample_examples:
        print("📚 Initializing example checkers...")
        init_example()

    # Setup output files
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = result_dir / f"generation_log_{timestamp}.log"
    result_file = result_dir / f"generation_results_{timestamp}.txt"
    summary_file = result_dir / f"generation_summary_{timestamp}.json"
    
    batch_summary = {
        "start_time": datetime.now().isoformat(),
        "total_commits": 0,
        "successful_commits": 0,
        "results": []
    }

    for line_num, line in enumerate(content.splitlines(), 1):
        if result_content and line in result_content:
            if line + ",False" in result_content or line + ",True" in result_content:
                print(f"⏭️  Skipping {line} (already processed)")
                logger.info(f"Skip {line}")
                continue
                
        commit_id, commit_type = line.split(",")
        batch_summary["total_commits"] += 1
        
        print(f"\n📦 Processing commit {line_num}: {commit_id}")
        print(f"🏷️  Type: {commit_type}")
        
        try:
            checker_results, summary = gen_checker_worker(
                commit_id,
                commit_type,
                use_multi=use_multi,
                use_general=use_general,
                no_utility=no_utility,
                sample_examples=sample_examples,
            )
            
            # Log results
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} {checker_results}\n")
            
            with open(result_file, "a") as fres:
                correct = any([TP > 0 and TN > 0 for _, TP, TN in checker_results])
                fres.write(f"{commit_id},{commit_type},{correct}\n")
            
            batch_summary["results"].append(summary.to_dict())
            if summary.perfect_checkers > 0:
                batch_summary["successful_commits"] += 1
                
            summary.print_summary()
            
        except Exception as e:
            error_msg = str(e).replace("\n", " ")
            print(f"❌ Error processing {commit_id}: {error_msg}")
            logger.error(f"Error processing {commit_id}: {e}")
            
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} ERROR: {error_msg}\n")
            with open(result_file, "a") as fres:
                fres.write(f"{commit_id},{commit_type},Exception\n")
    
    # Save batch summary
    batch_summary["end_time"] = datetime.now().isoformat()
    batch_summary["success_rate"] = batch_summary["successful_commits"] / max(batch_summary["total_commits"], 1)
    
    with open(summary_file, "w") as f:
        json.dump(batch_summary, f, indent=2)
    
    print(f"\n🎊 Batch Complete!")
    print(f"📊 Success Rate: {batch_summary['successful_commits']}/{batch_summary['total_commits']}")
    print(f"📄 Summary saved to: {summary_file}")


def gen_checker_worker(
    commit_id,
    commit_type,
    use_multi=True,
    use_plan_feedback=False,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    """Generate checkers for one commit with improved progress tracking."""

    progress = GenerationProgress()
    analysis_backend = global_config.backend
    target = global_config.target

    checker_results = []
    checker_data_list: List[CheckerData] = []
    checker_nums = global_config.get("checker_nums")

    id = f"AllGen-{commit_type}-{commit_id}"
    result_dir = Path(global_config.result_dir)
    
    # Build directory structure
    _build_directory(id)
    
    # Create organized output structure
    output_dir = result_dir / id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save metadata
    metadata = {
        "commit_id": commit_id,
        "commit_type": commit_type,
        "generation_config": {
            "use_multi": use_multi,
            "use_general": use_general,
            "no_utility": no_utility,
            "sample_examples": sample_examples,
            "checker_nums": checker_nums
        },
        "start_time": datetime.now().isoformat()
    }
    
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    patch = target.get_patch(commit_id)
    (output_dir / "commit_id.txt").write_text(commit_id)
    (output_dir / "patch.md").write_text(patch)

    # Check for existing results
    ranking_file = output_dir / "ranking.txt"
    if ranking_file.exists():
        checker_results = eval(ranking_file.read_text())
        has_perfect = any([TP > 0 and TN > 0 for _, TP, TN in checker_results])
        if has_perfect:
            print("🎉 Perfect checker already exists!")
            logger.info(f"Perfect checker found for {id}")
            
            summary = GenerationSummary(
                commit_id=commit_id,
                commit_type=commit_type,
                total_checkers=len(checker_results),
                successful_checkers=len([r for r in checker_results if r[1] > 0 or r[2] > 0]),
                perfect_checkers=len([r for r in checker_results if r[1] > 0 and r[2] > 0]),
                best_tp=max([r[1] for r in checker_results], default=0),
                best_tn=max([r[2] for r in checker_results], default=0),
                total_time=0
            )
            return checker_results, summary

    # Generate checkers
    errors = []
    for i in range(len(checker_results), checker_nums):
        print(f"\n🔄 Generating checker {i+1}/{checker_nums}")
        
        checker_data = CheckerData(commit_id, commit_type, result_dir, i, patch)
        
        # Create organized intermediate directory
        intermediate_dir = output_dir / "generation" / f"checker_{i:02d}"
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        try:
            if use_multi:
                # Step 1: Pattern Extraction
                step_name = progress.start_step("🧩 Pattern Extraction")
                pattern = patch2pattern(id, i, patch, use_general=use_general)
                progress.complete_step(step_name, f"Extracted {len(pattern)} chars")
                
                # Step 2: Plan Generation  
                step_name = progress.start_step("📋 Plan Generation")
                plan = pattern2plan(
                    id, i, pattern, patch,
                    no_utility=no_utility,
                    sample_examples=sample_examples,
                )
                refined_plan = plan
                progress.complete_step(step_name, f"Generated {len(plan.splitlines())} line plan")
                
                # Step 3: Code Generation
                step_name = progress.start_step("💻 Code Generation")
                checker_code = plan2checker(
                    id, i, pattern, refined_plan, patch,
                    no_utility=no_utility,
                    sample_examples=sample_examples,
                )
                progress.complete_step(step_name, f"Generated {len(checker_code.splitlines())} lines")
            else:
                step_name = progress.start_step("💻 Direct Code Generation")
                pattern = ""
                plan = ""
                refined_plan = ""
                checker_code = patch2checker(id, i, patch)
                progress.complete_step(step_name, f"Generated {len(checker_code.splitlines())} lines")

            checker_code = extract_checker_code(checker_code)
            
            # Update checker data
            checker_data.pattern = pattern
            checker_data.plan = plan
            checker_data.initial_checker_code = checker_code

            # Save intermediate files with clear naming
            (intermediate_dir / "01_pattern.txt").write_text(pattern)
            (intermediate_dir / "02_plan.txt").write_text(plan)
            (intermediate_dir / "03_refined_plan.txt").write_text(refined_plan)
            (intermediate_dir / "04_initial_code.cpp").write_text(checker_code)

            # Step 4: Syntax Repair
            step_name = progress.start_step("🔧 Syntax Repair")
            ret, repaired_checker_code = repair_checker(
                id=id,
                repair_name=f"syntax-repair-{i:02d}",
                max_idx=4,
                intermediate_dir=intermediate_dir,
                checker_code=checker_code,
            )
            
            if not ret:
                error_msg = f"Failed to generate compilable checker {i}"
                progress.fail_step(step_name, error_msg)
                errors.append(error_msg)
                checker_results.append((i, -10, -10))
                checker_data_list.append(checker_data)
                continue
                
            progress.complete_step(step_name, "Compilation successful")
            checker_data.repaired_checker_code = repaired_checker_code

            # Save repaired code
            (intermediate_dir / "05_repaired_code.cpp").write_text(repaired_checker_code)
            
            # Also save in checkers directory for compatibility
            checkers_dir = output_dir / "checkers"
            checkers_dir.mkdir(parents=True, exist_ok=True)
            (checkers_dir / f"checker_{i:02d}.cpp").write_text(repaired_checker_code)

            # Step 5: Validation
            step_name = progress.start_step("✅ Validation")
            TP, TN = analysis_backend.validate_checker(
                repaired_checker_code,
                commit_id,
                patch,
                target,
                skip_build_checker=True,
            )
            
            # Update checker data
            checker_data.tp_score = TP
            checker_data.tn_score = TN
            checker_results.append((i, TP, TN))
            checker_data_list.append(checker_data)
            
            progress.complete_step(step_name, f"TP: {TP}, TN: {TN}")
            
            # Save validation results
            validation_result = {
                "checker_id": i,
                "tp_score": TP,
                "tn_score": TN,
                "is_perfect": TP > 0 and TN > 0,
                "timestamp": datetime.now().isoformat()
            }
            (intermediate_dir / "06_validation.json").write_text(json.dumps(validation_result, indent=2))
            
            if TP > 0 and TN > 0:
                print(f"🎉 Perfect checker {i} found!")
                logger.info(f"Perfect checker {i} found: TP={TP}, TN={TN}")
                break
            elif TP == -1 and TN == -1:
                error_msg = f"Failed to evaluate checker {i}"
                errors.append(error_msg)
                logger.error(error_msg)
                break
                
        except Exception as e:
            error_msg = f"Error generating checker {i}: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
            checker_results.append((i, -10, -10))
            continue

    # Step 6: Summary Generation
    step_name = progress.start_step("📊 Summary Generation")
    
    # Save all checker data
    for checker_data in checker_data_list:
        checker_data.dump()
        checker_data.dump_dir()

    # Sort and save results
    checker_results = sorted(checker_results, key=lambda x: (x[1], x[2]), reverse=True)
    ranking_file.write_text(str(checker_results))
    
    # Create comprehensive summary
    summary = GenerationSummary(
        commit_id=commit_id,
        commit_type=commit_type,
        total_checkers=len(checker_results),
        successful_checkers=len([r for r in checker_results if r[1] > 0 or r[2] > 0]),
        perfect_checkers=len([r for r in checker_results if r[1] > 0 and r[2] > 0]),
        best_tp=max([r[1] for r in checker_results], default=0),
        best_tn=max([r[2] for r in checker_results], default=0),
        total_time=progress.get_total_time(),
        errors=errors
    )
    
    # Save summary
    (output_dir / "summary.json").write_text(json.dumps(summary.to_dict(), indent=2))
    
    progress.complete_step(step_name, f"Generated summary for {len(checker_results)} checkers")

    return checker_results, summary


def _build_directory(id: str):
    """Build the directory structure for the result."""
    basedir = Path(global_config.result_dir) / id
    basedir.mkdir(parents=True, exist_ok=True)
    
    # Create organized subdirectories
    subdirs = [
        "generation",      # Individual checker generation steps
        "checkers",        # Final checker files
        "build_logs",      # Compilation logs
        "prompt_history",  # LLM interaction history
        "validation"       # Validation results
    ]
    
    for subdir in subdirs:
        (basedir / subdir).mkdir(parents=True, exist_ok=True)
