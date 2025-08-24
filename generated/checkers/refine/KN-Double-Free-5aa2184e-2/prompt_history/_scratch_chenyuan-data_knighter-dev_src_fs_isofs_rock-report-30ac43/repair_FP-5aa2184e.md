# Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

# Instruction

Please analyze this false positive case and propose fixes to the checker code to eliminate this specific false positive while maintaining detection of true positives.

Please help improve this checker to eliminate the false positive while maintaining its ability to detect actual issues. Your solution should:

1. Identify the root cause of the false positive
2. Propose specific fixes to the checker logic
3. Consider edge cases and possible regressions
4. Maintain compatibility with Clang-18 API

Note, the repaired checker needs to still **detect the target buggy code**.

## Suggestions

1. Use proper visitor patterns and state tracking
2. Handle corner cases gracefully
3. You could register a program state like `REGISTER_MAP_WITH_PROGRAMSTATE(...)` to track the information you need.
4. Follow Clang Static Analyzer best practices for checker development
5. DO NOT remove any existing `#include` in the checker code.

You could add some functions like `bool isFalsePositive(...)` to help you define and detect the false positive.

# Utility Functions

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

/// \brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

# Clang Check Functions

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).


void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.


void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.


bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```


The following pattern is the checker designed to detect:

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

The patch that needs to be detected:

## Patch Description

net/mlx5: HWS, fixed double free in error flow of definer layout

Fix error flow bug that could lead to double free of a buffer
during a failure to calculate a suitable definer layout.

Fixes: 74a778b4a63f ("net/mlx5: HWS, added definers handling")
Signed-off-by: Yevgeny Kliteynik <kliteyn@nvidia.com>
Reviewed-by: Itamar Gozlan <igozlan@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mlx5hws_definer_calc_layout in drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
int
mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
			    struct mlx5hws_match_template *mt,
			    struct mlx5hws_definer *match_definer)
{
	u8 *match_hl;
	int ret;

	/* Union header-layout (hl) is used for creating a single definer
	 * field layout used with different bitmasks for hash and match.
	 */
	match_hl = kzalloc(MLX5_ST_SZ_BYTES(definer_hl), GFP_KERNEL);
	if (!match_hl)
		return -ENOMEM;

	/* Convert all mt items to header layout (hl)
	 * and allocate the match and range field copy array (fc & fcr).
	 */
	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
	if (ret) {
		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
		goto free_fc;
	}

	/* Find the match definer layout for header layout match union */
	ret = hws_definer_find_best_match_fit(ctx, match_definer, match_hl);
	if (ret) {
		if (ret == -E2BIG)
			mlx5hws_dbg(ctx,
				    "Failed to create match definer from header layout - E2BIG\n");
		else
			mlx5hws_err(ctx,
				    "Failed to create match definer from header layout (%d)\n",
				    ret);
		goto free_fc;
	}

	kfree(match_hl);
	return 0;

free_fc:
	kfree(mt->fc);

	kfree(match_hl);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
index d566d2ddf424..3f4c58bada37 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
@@ -1925,7 +1925,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
 	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
 	if (ret) {
 		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
-		goto free_fc;
+		goto free_match_hl;
 	}

 	/* Find the match definer layout for header layout match union */
@@ -1946,7 +1946,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,

 free_fc:
 	kfree(mt->fc);
-
+free_match_hl:
 	kfree(match_hl);
 	return ret;
 }
```


# False Positive Report

### Report Summary

File:| fs/isofs/rock.c
---|---
Warning:| line 130, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


3     |  *  linux/fs/isofs/rock.c
4     |  *
5     |  *  (C) 1992, 1993  Eric Youngdale
6     |  *
7     |  *  Rock Ridge Extensions to iso9660
8     |  */
9     |
10    | #include <linux/slab.h>
11    | #include <linux/pagemap.h>
12    |
13    | #include "isofs.h"
14    | #include "rock.h"
15    |
16    | /*
17    |  * These functions are designed to read the system areas of a directory record
18    |  * and extract relevant information.  There are different functions provided
19    |  * depending upon what information we need at the time.  One function fills
20    |  * out an inode structure, a second one extracts a filename, a third one
21    |  * returns a symbolic link name, and a fourth one returns the extent number
22    |  * for the file.
23    |  */
24    |
25    | #define SIG(A,B) ((A) | ((B) << 8))	/* isonum_721() */
26    |
27    | struct rock_state {
28    |  void *buffer;
29    |  unsigned char *chr;
30    |  int len;
31    |  int cont_size;
32    |  int cont_extent;
33    |  int cont_offset;
34    |  int cont_loops;
35    |  struct inode *inode;
36    | };
37    |
38    | /*
39    |  * This is a way of ensuring that we have something in the system
40    |  * use fields that is compatible with Rock Ridge.  Return zero on success.
41    |  */
42    |
43    | static int check_sp(struct rock_ridge *rr, struct inode *inode)
44    | {
45    |  if (rr->u.SP.magic[0] != 0xbe)
46    |  return -1;
47    |  if (rr->u.SP.magic[1] != 0xef)
48    |  return -1;
49    | 	ISOFS_SB(inode->i_sb)->s_rock_offset = rr->u.SP.skip;
50    |  return 0;
51    | }
52    |
53    | static void setup_rock_ridge(struct iso_directory_record *de,
54    |  struct inode *inode, struct rock_state *rs)
55    | {
56    | 	rs->len = sizeof(struct iso_directory_record) + de->name_len[0];
57    |  if (rs->len & 1)
58    | 		(rs->len)++;
59    | 	rs->chr = (unsigned char *)de + rs->len;
60    | 	rs->len = *((unsigned char *)de) - rs->len;
61    |  if (rs->len < 0)
62    | 		rs->len = 0;
63    |
64    |  if (ISOFS_SB(inode->i_sb)->s_rock_offset != -1) {
65    | 		rs->len -= ISOFS_SB(inode->i_sb)->s_rock_offset;
66    | 		rs->chr += ISOFS_SB(inode->i_sb)->s_rock_offset;
67    |  if (rs->len < 0)
68    | 			rs->len = 0;
69    | 	}
70    | }
71    |
72    | static void init_rock_state(struct rock_state *rs, struct inode *inode)
73    | {
74    |  memset(rs, 0, sizeof(*rs));
75    | 	rs->inode = inode;
76    | }
77    |
78    | /* Maximum number of Rock Ridge continuation entries */
79    | #define RR_MAX_CE_ENTRIES 32
80    |
81    | /*
82    |  * Returns 0 if the caller should continue scanning, 1 if the scan must end
83    |  * and -ve on error.
84    |  */
85    | static int rock_continue(struct rock_state *rs)
86    | {
87    |  int ret = 1;
88    |  int blocksize = 1 << rs->inode->i_blkbits;
    10←Assuming right operand of bit shift is less than 32→
89    |  const int min_de_size = offsetof(struct rock_ridge, u);
90    |
91    | 	kfree(rs->buffer);
92    | 	rs->buffer = NULL;
93    |
94    |  if ((unsigned)rs->cont_offset > blocksize - min_de_size ||
    11←Assuming the condition is false→
    14←Taking false branch→
95    |  (unsigned)rs->cont_size > blocksize ||
    12←Assuming 'blocksize' is >= field 'cont_size'→
96    |  (unsigned)(rs->cont_offset + rs->cont_size) > blocksize) {
    13←Assuming the condition is false→
97    |  printk(KERN_NOTICE "rock: corrupted directory entry. "
98    |  "extent=%d, offset=%d, size=%d\n",
99    |  rs->cont_extent, rs->cont_offset, rs->cont_size);
100   | 		ret = -EIO;
101   |  goto out;
102   | 	}
103   |
104   |  if (rs->cont_extent) {
    15←Assuming field 'cont_extent' is not equal to 0→
    16←Taking true branch→
105   |  struct buffer_head *bh;
106   |
107   | 		rs->buffer = kmalloc(rs->cont_size, GFP_KERNEL);
108   |  if (!rs->buffer) {
    17←Assuming field 'buffer' is non-null→
    18←Taking false branch→
109   | 			ret = -ENOMEM;
110   |  goto out;
111   | 		}
112   |  ret = -EIO;
113   |  if (++rs->cont_loops >= RR_MAX_CE_ENTRIES)
    19←Assuming the condition is true→
    20←Taking true branch→
114   |  goto out;
    21←Control jumps to line 130→
115   | 		bh = sb_bread(rs->inode->i_sb, rs->cont_extent);
116   |  if (bh) {
117   |  memcpy(rs->buffer, bh->b_data + rs->cont_offset,
118   |  rs->cont_size);
119   | 			put_bh(bh);
120   | 			rs->chr = rs->buffer;
121   | 			rs->len = rs->cont_size;
122   | 			rs->cont_extent = 0;
123   | 			rs->cont_size = 0;
124   | 			rs->cont_offset = 0;
125   |  return 0;
126   | 		}
127   |  printk("Unable to read rock-ridge attributes\n");
128   | 	}
129   | out:
130   |  kfree(rs->buffer);
    22←Freeing unowned field in shared error label; possible double free
131   | 	rs->buffer = NULL;
132   |  return ret;
133   | }
134   |
135   | /*
136   |  * We think there's a record of type `sig' at rs->chr.  Parse the signature
137   |  * and make sure that there's really room for a record of that type.
138   |  */
139   | static int rock_check_overflow(struct rock_state *rs, int sig)
140   | {
141   |  int len;
142   |
143   |  switch (sig) {
144   |  case SIG('S', 'P'):
145   | 		len = sizeof(struct SU_SP_s);
146   |  break;
147   |  case SIG('C', 'E'):
148   | 		len = sizeof(struct SU_CE_s);
149   |  break;
150   |  case SIG('E', 'R'):
151   | 		len = sizeof(struct SU_ER_s);
152   |  break;
153   |  case SIG('R', 'R'):
154   | 		len = sizeof(struct RR_RR_s);
155   |  break;
156   |  case SIG('P', 'X'):
157   | 		len = sizeof(struct RR_PX_s);
158   |  break;
159   |  case SIG('P', 'N'):
160   | 		len = sizeof(struct RR_PN_s);
639   | 		slp = (struct SL_component *)((char *)slp + slp->len + 2);
640   |
641   |  if (slen < 2) {
642   |  /*
643   |  * If there is another SL record, and this component
644   |  * record isn't continued, then add a slash.
645   |  */
646   |  if ((!rootflag) && (rr->u.SL.flags & 1) &&
647   | 			    !(oldslp->flags & 1)) {
648   |  if (rpnt >= plimit)
649   |  return NULL;
650   | 				*rpnt++ = '/';
651   | 			}
652   |  break;
653   | 		}
654   |
655   |  /*
656   |  * If this component record isn't continued, then append a '/'.
657   |  */
658   |  if (!rootflag && !(oldslp->flags & 1)) {
659   |  if (rpnt >= plimit)
660   |  return NULL;
661   | 			*rpnt++ = '/';
662   | 		}
663   | 	}
664   |  return rpnt;
665   | }
666   |
667   | int parse_rock_ridge_inode(struct iso_directory_record *de, struct inode *inode,
668   |  int relocated)
669   | {
670   |  int flags = relocated ? RR_RELOC_DE : 0;
671   |  int result = parse_rock_ridge_inode_internal(de, inode, flags);
672   |
673   |  /*
674   |  * if rockridge flag was reset and we didn't look for attributes
675   |  * behind eventual XA attributes, have a look there
676   |  */
677   |  if ((ISOFS_SB(inode->i_sb)->s_rock_offset == -1)
678   | 	    && (ISOFS_SB(inode->i_sb)->s_rock == 2)) {
679   | 		result = parse_rock_ridge_inode_internal(de, inode,
680   | 							 flags | RR_REGARD_XA);
681   | 	}
682   |  return result;
683   | }
684   |
685   | /*
686   |  * read_folio() for symlinks: reads symlink contents into the folio and either
687   |  * makes it uptodate and returns 0 or returns error (-EIO)
688   |  */
689   | static int rock_ridge_symlink_read_folio(struct file *file, struct folio *folio)
690   | {
691   |  struct page *page = &folio->page;
692   |  struct inode *inode = page->mapping->host;
693   |  struct iso_inode_info *ei = ISOFS_I(inode);
694   |  struct isofs_sb_info *sbi = ISOFS_SB(inode->i_sb);
695   |  char *link = page_address(page);
696   |  unsigned long bufsize = ISOFS_BUFFER_SIZE(inode);
697   |  struct buffer_head *bh;
698   |  char *rpnt = link;
699   |  unsigned char *pnt;
700   |  struct iso_directory_record *raw_de;
701   |  unsigned long block, offset;
702   |  int sig;
703   |  struct rock_ridge *rr;
704   |  struct rock_state rs;
705   |  int ret;
706   |
707   |  if (!sbi->s_rock)
    1Assuming field 's_rock' is not equal to 0→
    2←Taking false branch→
708   |  goto error;
709   |
710   |  init_rock_state(&rs, inode);
711   | 	block = ei->i_iget5_block;
712   | 	bh = sb_bread(inode->i_sb, block);
713   |  if (!bh)
    3←Assuming 'bh' is non-null→
    4←Taking false branch→
714   |  goto out_noread;
715   |
716   |  offset = ei->i_iget5_offset;
717   | 	pnt = (unsigned char *)bh->b_data + offset;
718   |
719   | 	raw_de = (struct iso_directory_record *)pnt;
720   |
721   |  /*
722   |  * If we go past the end of the buffer, there is some sort of error.
723   |  */
724   |  if (offset + *pnt > bufsize)
    5←Assuming the condition is false→
    6←Taking false branch→
725   |  goto out_bad_span;
726   |
727   |  /*
728   |  * Now test for possible Rock Ridge extensions which will override
729   |  * some of these numbers in the inode structure.
730   |  */
731   |
732   |  setup_rock_ridge(raw_de, inode, &rs);
733   |
734   | repeat:
735   |  while (rs.len > 2) { /* There may be one byte for padding somewhere */
    7←Assuming field 'len' is <= 2→
    8←Loop condition is false. Execution continues on line 772→
736   | 		rr = (struct rock_ridge *)rs.chr;
737   |  if (rr->len < 3)
738   |  goto out;	/* Something got screwed up here */
739   | 		sig = isonum_721(rs.chr);
740   |  if (rock_check_overflow(&rs, sig))
741   |  goto out;
742   | 		rs.chr += rr->len;
743   | 		rs.len -= rr->len;
744   |  if (rs.len < 0)
745   |  goto out;	/* corrupted isofs */
746   |
747   |  switch (sig) {
748   |  case SIG('R', 'R'):
749   |  if ((rr->u.RR.flags[0] & RR_SL) == 0)
750   |  goto out;
751   |  break;
752   |  case SIG('S', 'P'):
753   |  if (check_sp(rr, inode))
754   |  goto out;
755   |  break;
756   |  case SIG('S', 'L'):
757   | 			rpnt = get_symlink_chunk(rpnt, rr,
758   | 						 link + (PAGE_SIZE - 1));
759   |  if (rpnt == NULL)
760   |  goto out;
761   |  break;
762   |  case SIG('C', 'E'):
763   |  /* This tells is if there is a continuation record */
764   | 			rs.cont_extent = isonum_733(rr->u.CE.extent);
765   | 			rs.cont_offset = isonum_733(rr->u.CE.offset);
766   | 			rs.cont_size = isonum_733(rr->u.CE.size);
767   |  break;
768   |  default:
769   |  break;
770   | 		}
771   | 	}
772   |  ret = rock_continue(&rs);
    9←Calling 'rock_continue'→
773   |  if (ret == 0)
774   |  goto repeat;
775   |  if (ret < 0)
776   |  goto fail;
777   |
778   |  if (rpnt == link)
779   |  goto fail;
780   | 	brelse(bh);
781   | 	*rpnt = '\0';
782   | 	SetPageUptodate(page);
783   | 	unlock_page(page);
784   |  return 0;
785   |
786   |  /* error exit from macro */
787   | out:
788   | 	kfree(rs.buffer);
789   |  goto fail;
790   | out_noread:
791   |  printk("unable to read i-node block");
792   |  goto fail;
793   | out_bad_span:
794   |  printk("symlink spans iso9660 blocks\n");
795   | fail:
796   | 	brelse(bh);
797   | error:
798   | 	SetPageError(page);
799   | 	unlock_page(page);
800   |  return -EIO;
801   | }
802   |

Analysis:
- Decision: NotABug
- Reason: The flagged pattern does not match the target bug pattern and is not a real bug. In rock_continue(), rs->buffer is intentionally freed at the start to release any previous continuation buffer (kfree + NULL). If a new continuation is needed, a fresh buffer is kmalloc’d. On error paths (including the CE loop-limit case), the function jumps to the shared out label, which frees the currently owned buffer once. There is no double free of the same pointer: the first kfree is for the previous buffer (then rs->buffer is set to NULL), and if a new buffer was allocated, the final kfree at out frees that new allocation exactly once. If no new allocation occurred, kfree(NULL) is a no-op. Moreover, the caller’s cleanup does not double-free either: when rock_continue() returns an error (ret < 0), the caller goes to fail (not its out label), so it does not free rs.buffer again. This is unlike the target bug pattern where a shared error label frees memory that may be callee-managed or already freed; here the ownership and lifetime of rs->buffer are correctly managed within rock_continue(), and the cleanup is safe.

# Checker
```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: symbols returned by allocators.
REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
// Program state: regions that this function explicitly owns (assigned an allocator return).
REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
                             check::BeginFunction,
                             check::EndFunction,
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Per-function: how many gotos target each label.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, unsigned>> FuncLabelIncoming;

  // Per-function: fields directly assigned from ANY function call within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallySetByCallFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from a function call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstSetByCallLoc;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to perform case-insensitive substring search using lowercase conversion.
  static bool containsLower(StringRef Haystack, StringRef Needle) {
    std::string Lower = Haystack.lower();
    return StringRef(Lower).contains(Needle);
  }

  static bool isPointerType(QualType QT) {
    return QT->isPointerType() || QT->isAnyPointerType();
  }

  // Helper to collect labels, gotos, and fields locally assigned from function calls.
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallySetByCallFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstSetLoc;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // Only consider assignments of pointer-typed fields from function calls.
      const ValueDecl *VD = ME->getMemberDecl();
      if (!VD)
        return true;
      QualType LT = VD->getType();
      if (!isPointerType(LT))
        return true;

      if (const auto *FD = dyn_cast<FieldDecl>(VD)) {
        const FieldDecl *CanonFD = FD->getCanonicalDecl();
        LocallySetByCallFields.insert(CanonFD);
        SourceLocation CurLoc = BO->getBeginLoc();
        auto It = FirstSetLoc.find(CanonFD);
        if (It == FirstSetLoc.end()) {
          FirstSetLoc[CanonFD] = CurLoc;
        } else {
          const SourceManager &SM = C.getSourceManager();
          if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
            It->second = CurLoc;
        }
      }
      return true;
    }

    // Unused here but kept for potential future refinements.
    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *N : AllocNames)
          if (Name.equals(N))
            return true;
      }

      // Fallback to source text substring match.
      for (const char *N : AllocNames) {
        if (ExprHasName(CE, N, C))
          return true;
      }
      return false;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;

  // Identify free-like functions and which parameter indices are the freed pointers.
  bool getFreeLikeParamIndices(const CallEvent &Call,
                               llvm::SmallVectorImpl<unsigned> &Idxs) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const Expr *FreedArgE, const MemberExpr *FreedME,
                       const CallEvent &Call, const LabelStmt *EnclosingLabel,
                       CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves directly to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

  // Additional gating: check whether the target label has any error-like incoming goto.
  bool labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const;

  // Helpers for "error-ish" classification.
  bool labelNameLooksErrorish(const LabelStmt *LS) const;
  bool gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const;
  bool condLooksErrorish(const Expr *Cond, CheckerContext &C) const;
  const Expr *stripWrapperCalls(const Expr *E, CheckerContext &C) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  FuncInfoCollector Collector(C);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  // Build incoming goto counts and per-label goto lists.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>> LabelToGotos;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
    LabelToGotos[LS].push_back(GS);
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallySetByCallFields[FD] = std::move(Collector.LocallySetByCallFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);

  // Store earliest assignment-from-call locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstSetLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstSetByCallLoc[FD] = std::move(Earliest);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  StringRef Name = FD->getName();

  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : Names) {
    if (Name.equals(N))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getFreeLikeParamIndices(const CallEvent &Call,
                                               llvm::SmallVectorImpl<unsigned> &Idxs) const {
  Idxs.clear();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  // Exact matches only; avoid substring matches like "devm_kfree" triggering "kfree".
  if (Name.equals("kfree") || Name.equals("kvfree") || Name.equals("vfree")) {
    if (Call.getNumArgs() >= 1)
      Idxs.push_back(0);
  } else if (Name.equals("devm_kfree")) {
    if (Call.getNumArgs() >= 2)
      Idxs.push_back(1); // freed pointer is the second argument
  } else {
    return false;
  }
  return !Idxs.empty();
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-assigned-from-call fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallySetByCallFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstSetByCallLoc.erase(FD);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef RetSym = Ret.getAsSymbol();
  if (!RetSym)
    return;

  if (!State->contains<AllocSymSet>(RetSym)) {
    State = State->add<AllocSymSet>(RetSym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    // Mark the precise region as owned.
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
    }
    // Also mark the base region to be robust against field/base conversions.
    const MemRegion *Base = DstReg->getBaseRegion();
    if (Base && !State->contains<OwnedRegionSet>(Base)) {
      State = State->add<OwnedRegionSet>(Base);
    }
    C.addTransition(State);
  }
}

const ParmVarDecl *SAGenTestChecker::getDirectBaseParam(const Expr *BaseE) const {
  if (!BaseE)
    return nullptr;

  const Expr *E = BaseE;
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      UnaryOperatorKind Op = UO->getOpcode();
      if (Op == UO_Deref || Op == UO_AddrOf) {
        E = UO->getSubExpr();
        continue;
      }
    }
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      E = ASE->getBase();
      continue;
    }
    break;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

const Expr *SAGenTestChecker::stripWrapperCalls(const Expr *E, CheckerContext &C) const {
  const Expr *Cur = E ? E->IgnoreParenImpCasts() : nullptr;
  while (const auto *CE = dyn_cast_or_null<CallExpr>(Cur)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    StringRef Name = FD ? FD->getName() : StringRef();
    // Common kernel wrappers/macros lowered as calls we want to peel.
    if (Name.equals("unlikely") || Name.equals("likely") ||
        Name.equals("__builtin_expect")) {
      if (CE->getNumArgs() > 0) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  return Cur ? Cur->IgnoreParenImpCasts() : nullptr;
}

bool SAGenTestChecker::condLooksErrorish(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return false;

  const Expr *E = stripWrapperCalls(Cond, C);
  if (!E)
    return false;

  // if (ret) or if (!ret) patterns where 'ret' is a typical error code variable.
  auto LooksLikeErrVar = [](StringRef N) {
    return N.equals("ret") || N.equals("rc") || N.equals("err") || N.equals("error") || N.equals("status");
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (LooksLikeErrVar(VD->getName()))
        return true;
    }
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const auto *D = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
        if (const auto *VD = dyn_cast<VarDecl>(D->getDecl()))
          if (LooksLikeErrVar(VD->getName()))
            return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() || BO->getOpcode() == BO_NE || BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      auto IsZeroOrNegConst = [](const Expr *X) -> bool {
        if (const auto *IL = dyn_cast<IntegerLiteral>(X)) {
          return IL->getValue().isZero(); // zero
        }
        return false;
      };
      auto IsErrVar = [&](const Expr *X) -> bool {
        if (const auto *DR = dyn_cast<DeclRefExpr>(X))
          if (const auto *VD = dyn_cast<VarDecl>(DR->getDecl()))
            return LooksLikeErrVar(VD->getName());
        return false;
      };
      // ret != 0, ret < 0, 0 != ret, etc.
      if ((IsErrVar(L) && IsZeroOrNegConst(R)) || (IsErrVar(R) && IsZeroOrNegConst(L)))
        return true;
    }
  }

  // if (IS_ERR(ptr)) or IS_ERR_OR_NULL(ptr)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef N = FD->getName();
      if (N.equals("IS_ERR") || N.equals("IS_ERR_OR_NULL") || N.equals("IS_ERR_VALUE"))
        return true;
    } else {
      // Fallback: text search in the expression for kernel helpers.
      if (ExprHasName(E, "IS_ERR", C) || ExprHasName(E, "IS_ERR_OR_NULL", C) || ExprHasName(E, "IS_ERR_VALUE", C))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::labelNameLooksErrorish(const LabelStmt *LS) const {
  if (!LS || !LS->getDecl())
    return false;
  StringRef N = LS->getDecl()->getName();
  // Common error cleanup labels in kernel code.
  return containsLower(N, "err") || containsLower(N, "error") ||
         containsLower(N, "fail") || containsLower(N, "free") ||
         containsLower(N, "cleanup") || containsLower(N, "out_err");
}

bool SAGenTestChecker::gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const {
  if (!GS)
    return false;

  // If there's an enclosing if-statement, examine its condition.
  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(GS, C)) {
    if (const Expr *Cond = IS->getCond()) {
      if (condLooksErrorish(Cond, C))
        return true;
    }
  }

  // Otherwise, fall back to label name being errorish.
  const LabelDecl *LD = GS->getLabel();
  if (LD) {
    StringRef N = LD->getName();
    if (containsLower(N, "err") || containsLower(N, "error") ||
        containsLower(N, "fail") || containsLower(N, "free") ||
        containsLower(N, "cleanup") || containsLower(N, "out_err"))
      return true;
  }
  return false;
}

bool SAGenTestChecker::labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const {
  if (!FD || !LS)
    return false;
  auto ItF = FuncLabelGotos.find(FD);
  if (ItF == FuncLabelGotos.end())
    return false;
  auto It = ItF->second.find(LS);
  if (It == ItF->second.end())
    return false;

  // If label name looks errorish, that's sufficient.
  if (labelNameLooksErrorish(LS))
    return true;

  const auto &Gotos = It->second;
  for (const GotoStmt *GS : Gotos) {
    if (gotoLooksErrorish(GS, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFalsePositive(const Expr *FreedArgE,
                                       const MemberExpr *FreedME,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 0) If the label does not look like an error path for any of its incoming gotos,
  //    this is very likely a normal cleanup label (e.g. "out") -> suppress.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && EnclosingLabel && !labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return true;

  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  if (FreedArgE) {
    SVal ArgVal = C.getSVal(FreedArgE);
    if (ArgVal.isZeroConstant())
      return true;
  }

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  if (FreedArgE) {
    const MemRegion *FreedReg = getMemRegionFromExpr(FreedArgE, C);
    if (FreedReg) {
      const MemRegion *Base = FreedReg->getBaseRegion();
      ProgramStateRef State = C.getState();
      if (State->contains<OwnedRegionSet>(FreedReg) ||
          (Base && State->contains<OwnedRegionSet>(Base))) {
        return true;
      }
    }
  }

  // 3) If all incoming gotos to this label lexically occur after the earliest assignment
  //    of this field from a function call in the same function, then the shared-label free
  //    is consistent with local ownership -> suppress.
  if (FD && FreedME) {
    const FieldDecl *FreedFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (FreedFD) {
      const FieldDecl *CanonFD = FreedFD->getCanonicalDecl();

      auto AssignItF = FuncFieldFirstSetByCallLoc.find(FD);
      auto GotoItF  = FuncLabelGotos.find(FD);
      if (AssignItF != FuncFieldFirstSetByCallLoc.end() &&
          GotoItF  != FuncLabelGotos.end()) {
        auto AssignIt = AssignItF->second.find(CanonFD);
        auto GLabelIt = GotoItF->second.find(EnclosingLabel);
        if (AssignIt != AssignItF->second.end() &&
            GLabelIt != GotoItF->second.end()) {
          SourceLocation FirstSetLoc = AssignIt->second;
          const auto &Gotos = GLabelIt->second;
          if (!Gotos.empty()) {
            const SourceManager &SM = C.getSourceManager();
            bool AnyBefore = false;
            for (const GotoStmt *GS : Gotos) {
              SourceLocation GLoc = GS->getGotoLoc();
              if (SM.isBeforeInTranslationUnit(GLoc, FirstSetLoc)) {
                AnyBefore = true;
                break;
              }
            }
            if (!AnyBefore) {
              // All incoming gotos occur after local assignment-from-call to this field.
              // Treat as owned in this function -> suppress.
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing unowned field in shared error label; possible double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> FreeIdxs;
  if (!getFreeLikeParamIndices(Call, FreeIdxs))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const LabelStmt *EnclosingLabel = findSpecificTypeInParents<LabelStmt>(Origin, C);
  if (!EnclosingLabel)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  auto Fit = FuncLabelIncoming.find(FD);
  if (Fit == FuncLabelIncoming.end())
    return;

  const auto &IncomingMap = Fit->second;
  auto Lit = IncomingMap.find(EnclosingLabel);
  unsigned Count = (Lit == IncomingMap.end()) ? 0u : Lit->second;

  // Only consider shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Only consider labels that look like error paths.
  if (!labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return;

  // Check each freed argument.
  for (unsigned ArgIndex : FreeIdxs) {
    const Expr *ArgE = Call.getArgExpr(ArgIndex);
    if (!ArgE)
      continue;

    // Only consider freeing a struct/union field like mt->fc.
    const Expr *Stripped = ArgE->IgnoreParenImpCasts();
    const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
    if (!FreedME)
      continue;

    // Only warn when the freed field belongs directly to a function parameter.
    // This matches the target buggy pattern (e.g., mt->fc) and suppresses cleanup of local/private state.
    const Expr *BaseE = FreedME->getBase();
    const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
    if (!BaseParam)
      continue;

    // Suppress known false positives.
    if (isFalsePositive(ArgE, FreedME, Call, EnclosingLabel, C))
      continue;

    reportFreeUnownedInSharedLabel(Call, C);
    // One report per call site is sufficient.
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing unowned fields in shared error labels that may cause double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

# Formatting

Please provide the whole checker code after fixing the false positive.
The refined code must be surrounded by ```cpp and ```.
Your response should be like:

Refinment Plan:
XXX

Refined Code:
```cpp
{{fixed checker code here}}
```
