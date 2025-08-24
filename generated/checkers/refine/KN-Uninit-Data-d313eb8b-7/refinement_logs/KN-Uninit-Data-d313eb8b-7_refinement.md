# Refinement Log for Checker: KN-Uninit-Data-d313eb8b-7

**Generated**: 2025-08-23 12:31:50
**Working Directory**: /scratch/chenyuan-data/knighter-dev/src
**Total Attempts**: 2

## Summary
- **Successful Refinements**: 1/2
- **Code Actually Changed**: 1/2 attempts
- **Final Status**: Perfect
- **Final Refined**: False
- **Final Code Changed**: NO
- **Total Objects Killed**: 5

## Detailed Attempt Log

### Attempt 1
- **Status**: Refined
- **Refined**: True
- **Code Changed**: ✓ YES
- **Reports**: 51
- **True Positives**: 0
- **False Positives**: 5
- **Precision**: 0.00%
- **Refine Attempts**: 5
- **Refine Attempt Details**:
  - Attempt 1: `refine-0-0`
    - Report ID: _scratch_chenyuan-data_knighter-dev_src_net_sched_sch_red-report-1472e5
    - Killed Objects: 6
    - Semantic Correct: YES
    - Objects: net/sched/sch_red.o, net/sched/sch_red.o, net/sched/cls_matchall.o...
  - Attempt 2: `refine-0-1`
    - Report ID: _scratch_chenyuan-data_knighter-dev_src_net_sched_sch_gred-report-52a614
    - Killed Objects: 1
    - Semantic Correct: YES
    - Objects: net/sched/sch_gred.o
  - Attempt 3: `refine-0-2`
    - Report ID: _scratch_chenyuan-data_knighter-dev_src_net_sched_cls_matchall-report-c03aac
    - Killed Objects: 1
    - Semantic Correct: YES
    - Objects: net/sched/cls_matchall.o
  - Attempt 4: `refine-0-3`
    - Report ID: _scratch_chenyuan-data_knighter-dev_src_net_sched_act_vlan-report-b46e23
    - Killed Objects: 1
    - Semantic Correct: YES
    - Objects: net/sched/act_vlan.o
  - Attempt 5: `refine-0-4`
    - Report ID: _scratch_chenyuan-data_knighter-dev_src_net_sched_cls_u32-report-443c55
    - Killed Objects: 1
    - Semantic Correct: NO
    - Objects: net/sched/cls_u32.o
- **Code Changes**: 347 → 524 lines

### Attempt 2
- **Status**: Perfect
- **Refined**: False
- **Code Changed**: ✗ NO
- **Reports**: 3
- **True Positives**: 0
- **False Positives**: 0
- **Refine Attempts**: 0
