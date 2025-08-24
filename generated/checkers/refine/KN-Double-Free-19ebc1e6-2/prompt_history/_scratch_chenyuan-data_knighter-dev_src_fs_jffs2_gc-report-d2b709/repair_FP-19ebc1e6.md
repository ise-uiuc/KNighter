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

Unconditional kfree() in a common cleanup label combined with a retry/replay loop, while the freed pointer is not reset to NULL on loop restart. This lets a dangling pointer value persist across iterations, so an early goto to the cleanup before reallocation triggers a second kfree() on already-freed memory.

Pattern sketch:
replay_again:
    /* ... */
    if (error_before_alloc)
        goto out;
    p = kmalloc(...);
    if (!p)
        goto out;
    /* ... */
out:
    kfree(p);     /* unconditional free */
    if (should_retry)
        goto replay_again;  /* p not reset to NULL -> possible double free on next early exit */

The patch that needs to be detected:

## Patch Description

smb: client: fix possible double free in smb2_set_ea()

Clang static checker(scan-build) warning：
fs/smb/client/smb2ops.c:1304:2: Attempt to free released memory.
 1304 |         kfree(ea);
      |         ^~~~~~~~~

There is a double free in such case:
'ea is initialized to NULL' -> 'first successful memory allocation for
ea' -> 'something failed, goto sea_exit' -> 'first memory release for ea'
-> 'goto replay_again' -> 'second goto sea_exit before allocate memory
for ea' -> 'second memory release for ea resulted in double free'.

Re-initialie 'ea' to NULL near to the replay_again label, it can fix this
double free problem.

Fixes: 4f1fffa23769 ("cifs: commands that are retried should have replay flag set")
Reviewed-by: Dan Carpenter <dan.carpenter@linaro.org>
Signed-off-by: Su Hui <suhui@nfschina.com>
Signed-off-by: Steve French <stfrench@microsoft.com>

## Buggy Code

```c
// Function: smb2_set_ea in fs/smb/client/smb2ops.c
static int
smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
	    const char *path, const char *ea_name, const void *ea_value,
	    const __u16 ea_value_len, const struct nls_table *nls_codepage,
	    struct cifs_sb_info *cifs_sb)
{
	struct smb2_compound_vars *vars;
	struct cifs_ses *ses = tcon->ses;
	struct TCP_Server_Info *server;
	struct smb_rqst *rqst;
	struct kvec *rsp_iov;
	__le16 *utf16_path = NULL;
	int ea_name_len = strlen(ea_name);
	int flags = CIFS_CP_CREATE_CLOSE_OP;
	int len;
	int resp_buftype[3];
	struct cifs_open_parms oparms;
	__u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_fid fid;
	unsigned int size[1];
	void *data[1];
	struct smb2_file_full_ea_info *ea = NULL;
	struct smb2_query_info_rsp *rsp;
	int rc, used_len = 0;
	int retries = 0, cur_sleep = 1;

replay_again:
	/* reinitialize for possible replay */
	flags = CIFS_CP_CREATE_CLOSE_OP;
	oplock = SMB2_OPLOCK_LEVEL_NONE;
	server = cifs_pick_channel(ses);

	if (smb3_encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	if (ea_name_len > 255)
		return -EINVAL;

	utf16_path = cifs_convert_path_to_utf16(path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	resp_buftype[0] = resp_buftype[1] = resp_buftype[2] = CIFS_NO_BUFFER;
	vars = kzalloc(sizeof(*vars), GFP_KERNEL);
	if (!vars) {
		rc = -ENOMEM;
		goto out_free_path;
	}
	rqst = vars->rqst;
	rsp_iov = vars->rsp_iov;

	if (ses->server->ops->query_all_EAs) {
		if (!ea_value) {
			rc = ses->server->ops->query_all_EAs(xid, tcon, path,
							     ea_name, NULL, 0,
							     cifs_sb);
			if (rc == -ENODATA)
				goto sea_exit;
		} else {
			/* If we are adding a attribute we should first check
			 * if there will be enough space available to store
			 * the new EA. If not we should not add it since we
			 * would not be able to even read the EAs back.
			 */
			rc = smb2_query_info_compound(xid, tcon, path,
				      FILE_READ_EA,
				      FILE_FULL_EA_INFORMATION,
				      SMB2_O_INFO_FILE,
				      CIFSMaxBufSize -
				      MAX_SMB2_CREATE_RESPONSE_SIZE -
				      MAX_SMB2_CLOSE_RESPONSE_SIZE,
				      &rsp_iov[1], &resp_buftype[1], cifs_sb);
			if (rc == 0) {
				rsp = (struct smb2_query_info_rsp *)rsp_iov[1].iov_base;
				used_len = le32_to_cpu(rsp->OutputBufferLength);
			}
			free_rsp_buf(resp_buftype[1], rsp_iov[1].iov_base);
			resp_buftype[1] = CIFS_NO_BUFFER;
			memset(&rsp_iov[1], 0, sizeof(rsp_iov[1]));
			rc = 0;

			/* Use a fudge factor of 256 bytes in case we collide
			 * with a different set_EAs command.
			 */
			if (CIFSMaxBufSize - MAX_SMB2_CREATE_RESPONSE_SIZE -
			   MAX_SMB2_CLOSE_RESPONSE_SIZE - 256 <
			   used_len + ea_name_len + ea_value_len + 1) {
				rc = -ENOSPC;
				goto sea_exit;
			}
		}
	}

	/* Open */
	rqst[0].rq_iov = vars->open_iov;
	rqst[0].rq_nvec = SMB2_CREATE_IOV_SIZE;

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.path = path,
		.desired_access = FILE_WRITE_EA,
		.disposition = FILE_OPEN,
		.create_options = cifs_create_options(cifs_sb, 0),
		.fid = &fid,
		.replay = !!(retries),
	};

	rc = SMB2_open_init(tcon, server,
			    &rqst[0], &oplock, &oparms, utf16_path);
	if (rc)
		goto sea_exit;
	smb2_set_next_command(tcon, &rqst[0]);


	/* Set Info */
	rqst[1].rq_iov = vars->si_iov;
	rqst[1].rq_nvec = 1;

	len = sizeof(*ea) + ea_name_len + ea_value_len + 1;
	ea = kzalloc(len, GFP_KERNEL);
	if (ea == NULL) {
		rc = -ENOMEM;
		goto sea_exit;
	}

	ea->ea_name_length = ea_name_len;
	ea->ea_value_length = cpu_to_le16(ea_value_len);
	memcpy(ea->ea_data, ea_name, ea_name_len + 1);
	memcpy(ea->ea_data + ea_name_len + 1, ea_value, ea_value_len);

	size[0] = len;
	data[0] = ea;

	rc = SMB2_set_info_init(tcon, server,
				&rqst[1], COMPOUND_FID,
				COMPOUND_FID, current->tgid,
				FILE_FULL_EA_INFORMATION,
				SMB2_O_INFO_FILE, 0, data, size);
	if (rc)
		goto sea_exit;
	smb2_set_next_command(tcon, &rqst[1]);
	smb2_set_related(&rqst[1]);

	/* Close */
	rqst[2].rq_iov = &vars->close_iov;
	rqst[2].rq_nvec = 1;
	rc = SMB2_close_init(tcon, server,
			     &rqst[2], COMPOUND_FID, COMPOUND_FID, false);
	if (rc)
		goto sea_exit;
	smb2_set_related(&rqst[2]);

	if (retries) {
		smb2_set_replay(server, &rqst[0]);
		smb2_set_replay(server, &rqst[1]);
		smb2_set_replay(server, &rqst[2]);
	}

	rc = compound_send_recv(xid, ses, server,
				flags, 3, rqst,
				resp_buftype, rsp_iov);
	/* no need to bump num_remote_opens because handle immediately closed */

 sea_exit:
	kfree(ea);
	SMB2_open_free(&rqst[0]);
	SMB2_set_info_free(&rqst[1]);
	SMB2_close_free(&rqst[2]);
	free_rsp_buf(resp_buftype[0], rsp_iov[0].iov_base);
	free_rsp_buf(resp_buftype[1], rsp_iov[1].iov_base);
	free_rsp_buf(resp_buftype[2], rsp_iov[2].iov_base);
	kfree(vars);
out_free_path:
	kfree(utf16_path);

	if (is_replayable_error(rc) &&
	    smb2_should_replay(tcon, &retries, &cur_sleep))
		goto replay_again;

	return rc;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/smb/client/smb2ops.c b/fs/smb/client/smb2ops.c
index 6b385fce3f2a..24a2aa04a108 100644
--- a/fs/smb/client/smb2ops.c
+++ b/fs/smb/client/smb2ops.c
@@ -1158,7 +1158,7 @@ smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
 	struct cifs_fid fid;
 	unsigned int size[1];
 	void *data[1];
-	struct smb2_file_full_ea_info *ea = NULL;
+	struct smb2_file_full_ea_info *ea;
 	struct smb2_query_info_rsp *rsp;
 	int rc, used_len = 0;
 	int retries = 0, cur_sleep = 1;
@@ -1179,6 +1179,7 @@ smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
 	if (!utf16_path)
 		return -ENOMEM;

+	ea = NULL;
 	resp_buftype[0] = resp_buftype[1] = resp_buftype[2] = CIFS_NO_BUFFER;
 	vars = kzalloc(sizeof(*vars), GFP_KERNEL);
 	if (!vars) {
```


# False Positive Report

### Report Summary

File:| fs/jffs2/gc.c
---|---
Warning:| line 751, column 2
Pointer freed in cleanup then retried without resetting to NULL; early goto
can double free

### Annotated Source Code


701   |
702   |  if (ret || (retlen != rawlen)) {
703   |  pr_notice("Write of %d bytes at 0x%08x failed. returned %d, retlen %zd\n",
704   |  rawlen, phys_ofs, ret, retlen);
705   |  if (retlen) {
706   | 			jffs2_add_physical_node_ref(c, phys_ofs | REF_OBSOLETE, rawlen, NULL);
707   | 		} else {
708   |  pr_notice("Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n",
709   |  phys_ofs);
710   | 		}
711   |  if (!retried) {
712   |  /* Try to reallocate space and retry */
713   | 			uint32_t dummy;
714   |  struct jffs2_eraseblock *jeb = &c->blocks[phys_ofs / c->sector_size];
715   |
716   | 			retried = 1;
717   |
718   |  jffs2_dbg(1, "Retrying failed write of REF_PRISTINE node.\n");
719   |
720   |  jffs2_dbg_acct_sanity_check(c,jeb);
721   | 			jffs2_dbg_acct_paranoia_check(c, jeb);
722   |
723   | 			ret = jffs2_reserve_space_gc(c, rawlen, &dummy, rawlen);
724   |  /* this is not the exact summary size of it,
725   |  it is only an upper estimation */
726   |
727   |  if (!ret) {
728   |  jffs2_dbg(1, "Allocated space at 0x%08x to retry failed write.\n",
729   |  phys_ofs);
730   |
731   |  jffs2_dbg_acct_sanity_check(c,jeb);
732   | 				jffs2_dbg_acct_paranoia_check(c, jeb);
733   |
734   |  goto retry;
735   | 			}
736   |  jffs2_dbg(1, "Failed to allocate space to retry failed write: %d!\n",
737   |  ret);
738   | 		}
739   |
740   |  if (!ret)
741   | 			ret = -EIO;
742   |  goto out_node;
743   | 	}
744   | 	jffs2_add_physical_node_ref(c, phys_ofs | REF_PRISTINE, rawlen, ic);
745   |
746   | 	jffs2_mark_node_obsolete(c, raw);
747   |  jffs2_dbg(1, "WHEEE! GC REF_PRISTINE node at 0x%08x succeeded\n",
748   |  ref_offset(raw));
749   |
750   |  out_node:
751   |  kfree(node);
    Pointer freed in cleanup then retried without resetting to NULL; early goto can double free
752   |  return ret;
753   |  bail:
754   | 	ret = -EBADFD;
755   |  goto out_node;
756   | }
757   |
758   | static int jffs2_garbage_collect_metadata(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
759   |  struct jffs2_inode_info *f, struct jffs2_full_dnode *fn)
760   | {
761   |  struct jffs2_full_dnode *new_fn;
762   |  struct jffs2_raw_inode ri;
763   |  struct jffs2_node_frag *last_frag;
764   |  union jffs2_device_node dev;
765   |  char *mdata = NULL;
766   |  int mdatalen = 0;
767   | 	uint32_t alloclen, ilen;
768   |  int ret;
769   |
770   |  if (S_ISBLK(JFFS2_F_I_MODE(f)) ||
771   |  S_ISCHR(JFFS2_F_I_MODE(f)) ) {
772   |  /* For these, we don't actually need to read the old node */
773   | 		mdatalen = jffs2_encode_dev(&dev, JFFS2_F_I_RDEV(f));
774   | 		mdata = (char *)&dev;
775   |  jffs2_dbg(1, "%s(): Writing %d bytes of kdev_t\n",
776   |  __func__, mdatalen);
777   | 	} else if (S_ISLNK(JFFS2_F_I_MODE(f))) {
778   | 		mdatalen = fn->size;
779   | 		mdata = kmalloc(fn->size, GFP_KERNEL);
780   |  if (!mdata) {
781   |  pr_warn("kmalloc of mdata failed in jffs2_garbage_collect_metadata()\n");

Analysis:
- Decision: NotABug
- Reason: The reported code does not match the target bug pattern. In this function, there is a single retry via a backward goto to the "retry" label that occurs only before entering the common cleanup. All paths that go to the "out_node" label execute kfree(node) and then immediately return; there is no loop or jump back to "retry" after the cleanup. Therefore, the freed pointer cannot persist into another iteration within the same invocation. The hallmark of the target pattern—unconditional kfree in a common cleanup combined with a retry/replay loop that restarts after cleanup without resetting the pointer—is absent. Here, node is never freed prior to the retry, and once freed at out_node, the function returns, preventing any second free in the same call.

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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallVector.h"
#include <vector>
#include <utility>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are necessary for this structural checker.

namespace {

struct LabelInfo {
  const LabelStmt *LStmt = nullptr;
  const LabelDecl *LDecl = nullptr;
  SourceLocation Loc;
};

struct GotoInfo {
  const GotoStmt *G = nullptr;
  const LabelDecl *Target = nullptr;
  SourceLocation Loc;
};

struct FreeSite {
  const VarDecl *P = nullptr;                 // pointer variable freed
  const LabelDecl *CleanupLabel = nullptr;    // label where free occurs
  const CallExpr *FreeCall = nullptr;         // kfree/kvfree call
  SourceLocation FreeLoc;
};

struct AssignInfo {
  const VarDecl *P = nullptr;
  SourceLocation Loc;
  bool ResetToNull = false;
};

class BodyScanner : public RecursiveASTVisitor<BodyScanner> {
public:
  BodyScanner(ASTContext &Ctx,
              std::vector<LabelInfo> &Labels,
              std::vector<GotoInfo> &Gotos,
              std::vector<FreeSite> &Frees,
              std::vector<AssignInfo> &Assigns)
      : Ctx(Ctx), SM(Ctx.getSourceManager()), Labels(Labels), Gotos(Gotos),
        Frees(Frees), Assigns(Assigns) {}

  bool VisitLabelStmt(LabelStmt *L) {
    LabelInfo Info;
    Info.LStmt = L;
    Info.LDecl = L->getDecl();
    Info.Loc = getExpansionLocSafe(L->getBeginLoc());
    Labels.push_back(Info);

    // Scan the sub-statement for free-like calls.
    if (Stmt *Sub = L->getSubStmt())
      collectFreesUnder(Sub, L->getDecl());

    return true;
  }

  bool VisitGotoStmt(GotoStmt *G) {
    GotoInfo GI;
    GI.G = G;
    GI.Target = G->getLabel();
    GI.Loc = getExpansionLocSafe(G->getGotoLoc());
    Gotos.push_back(GI);
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS();

    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return true;

    if (!VD->getType()->isAnyPointerType())
      return true;

    bool IsNull = isNullPointerExpr(RHS);
    AssignInfo AI;
    AI.P = VD;
    AI.Loc = getExpansionLocSafe(BO->getExprLoc());
    AI.ResetToNull = IsNull;
    Assigns.push_back(AI);
    return true;
  }

  bool VisitDeclStmt(DeclStmt *DS) {
    for (auto *D : DS->decls()) {
      auto *VD = dyn_cast<VarDecl>(D);
      if (!VD)
        continue;
      if (!VD->getType()->isAnyPointerType())
        continue;
      if (!VD->hasInit())
        continue;

      const Expr *Init = VD->getInit();
      bool IsNull = isNullPointerExpr(Init);
      AssignInfo AI;
      AI.P = VD;
      AI.Loc = getExpansionLocSafe(VD->getLocation());
      AI.ResetToNull = IsNull;
      Assigns.push_back(AI);
    }
    return true;
  }

private:
  ASTContext &Ctx;
  const SourceManager &SM;
  std::vector<LabelInfo> &Labels;
  std::vector<GotoInfo> &Gotos;
  std::vector<FreeSite> &Frees;
  std::vector<AssignInfo> &Assigns;

  SourceLocation getExpansionLocSafe(SourceLocation L) const {
    if (L.isInvalid())
      return L;
    return SM.getExpansionLoc(L);
  }

  static bool isFreeName(StringRef N) {
    return N == "kfree" || N == "kvfree";
  }

  bool isNullPointerExpr(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    // Use Clang's helper to decide null pointer constants
    return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull) !=
           Expr::NPCK_NotNull;
  }

  bool isFreeCallOnVar(const CallExpr *CE, const VarDecl *&OutVD) const {
    OutVD = nullptr;
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return false;
    const IdentifierInfo *II = FD->getIdentifier();
    if (!II)
      return false;
    if (!isFreeName(II->getName()))
      return false;

    if (CE->getNumArgs() < 1)
      return false;

    const Expr *Arg0 = CE->getArg(0)->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg0)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getType()->isAnyPointerType()) {
          OutVD = VD;
          return true;
        }
      }
    }
    return false;
  }

  void collectFreesUnder(Stmt *S, const LabelDecl *Where) {
    if (!S)
      return;

    // Local simple walker to look for CallExprs
    struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
      LocalVisitor(const BodyScanner &Outer, const LabelDecl *L,
                   std::vector<FreeSite> &Frees)
          : Outer(Outer), LDecl(L), Frees(Frees) {}

      bool VisitCallExpr(CallExpr *CE) {
        const VarDecl *VD = nullptr;
        if (Outer.isFreeCallOnVar(CE, VD) && VD) {
          FreeSite FS;
          FS.P = VD;
          FS.CleanupLabel = LDecl;
          FS.FreeCall = CE;
          FS.FreeLoc = Outer.getExpansionLocSafe(CE->getExprLoc());
          Frees.push_back(FS);
        }
        return true;
      }

      const BodyScanner &Outer;
      const LabelDecl *LDecl;
      std::vector<FreeSite> &Frees;
    };

    LocalVisitor LV(*this, Where, Frees);
    LV.TraverseStmt(S);
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker()
        : BT(new BugType(this, "Possible double free across retry loop", "Memory Error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:
      static SourceLocation getExpansionLocSafe(const SourceManager &SM, SourceLocation L) {
        if (L.isInvalid())
          return L;
        return SM.getExpansionLoc(L);
      }

      static bool before(const SourceManager &SM, SourceLocation A, SourceLocation B) {
        A = getExpansionLocSafe(SM, A);
        B = getExpansionLocSafe(SM, B);
        return SM.isBeforeInTranslationUnit(A, B);
      }

      static bool strictlyBetween(const SourceManager &SM, SourceLocation X,
                                  SourceLocation L, SourceLocation R) {
        return before(SM, L, X) && before(SM, X, R);
      }

      void detectAndReport(const FunctionDecl *FD,
                           const std::vector<LabelInfo> &Labels,
                           const std::vector<GotoInfo> &Gotos,
                           const std::vector<FreeSite> &Frees,
                           const std::vector<AssignInfo> &Assigns,
                           BugReporter &BR, ASTContext &AC) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  std::vector<LabelInfo> Labels;
  std::vector<GotoInfo> Gotos;
  std::vector<FreeSite> Frees;
  std::vector<AssignInfo> Assigns;

  BodyScanner Scanner(Ctx, Labels, Gotos, Frees, Assigns);
  Scanner.TraverseStmt(const_cast<Stmt *>(Body));

  detectAndReport(FD, Labels, Gotos, Frees, Assigns, BR, Ctx);
}

void SAGenTestChecker::detectAndReport(const FunctionDecl *FD,
                                       const std::vector<LabelInfo> &Labels,
                                       const std::vector<GotoInfo> &Gotos,
                                       const std::vector<FreeSite> &Frees,
                                       const std::vector<AssignInfo> &Assigns,
                                       BugReporter &BR, ASTContext &AC) const {
  const SourceManager &SM = AC.getSourceManager();

  auto getLabelLoc = [&](const LabelDecl *LD) -> SourceLocation {
    for (const auto &LI : Labels) {
      if (LI.LDecl == LD)
        return LI.Loc;
    }
    return SourceLocation();
  };

  for (const auto &FS : Frees) {
    if (!FS.P || !FS.CleanupLabel || !FS.FreeCall)
      continue;

    SourceLocation FreeLoc = FS.FreeLoc;
    SourceLocation CleanupLoc = getLabelLoc(FS.CleanupLabel);
    if (FreeLoc.isInvalid() || CleanupLoc.isInvalid())
      continue;

    // Find a backward goto (retry) after the free.
    for (const auto &GR : Gotos) {
      if (!GR.Target)
        continue;

      SourceLocation GoLoc = GR.Loc;
      SourceLocation TargetLoc = getLabelLoc(GR.Target);
      if (GoLoc.isInvalid() || TargetLoc.isInvalid())
        continue;

      // Must be: free ... goto restart_label; where restart_label is before free.
      if (!(before(SM, FreeLoc, GoLoc) && before(SM, TargetLoc, FreeLoc)))
        continue;

      // Safety check 1: reset to NULL between free and retry goto
      bool ResetBetween = false;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (AI.ResetToNull && strictlyBetween(SM, AI.Loc, FreeLoc, GoLoc)) {
          ResetBetween = true;
          break;
        }
      }
      if (ResetBetween)
        continue; // safe for this retry goto

      // Safety check 2: earliest assignment after restart label
      const AssignInfo *Earliest = nullptr;
      for (const auto &AI : Assigns) {
        if (AI.P != FS.P)
          continue;
        if (before(SM, TargetLoc, AI.Loc)) {
          if (!Earliest || before(SM, AI.Loc, Earliest->Loc))
            Earliest = &AI;
        }
      }

      // Look for an early goto to the cleanup label between restart label and earliest assignment.
      bool EarlyGotoToCleanup = false;
      for (const auto &GE : Gotos) {
        if (GE.Target != FS.CleanupLabel)
          continue;
        SourceLocation ELoc = GE.Loc;
        if (!before(SM, TargetLoc, ELoc))
          continue;
        if (Earliest) {
          if (before(SM, ELoc, Earliest->Loc)) {
            EarlyGotoToCleanup = true;
            break;
          }
        } else {
          // No assignment after restart; any early goto to cleanup after restart is problematic.
          EarlyGotoToCleanup = true;
          break;
        }
      }

      if (EarlyGotoToCleanup) {
        // Report at the free call location using a SourceLocation-based PathDiagnosticLocation.
        auto R = std::make_unique<BasicBugReport>(
            *BT,
            "Pointer freed in cleanup then retried without resetting to NULL; "
            "early goto can double free",
            PathDiagnosticLocation(FS.FreeLoc, SM));
        R->addRange(FS.FreeCall->getSourceRange());
        BR.emitReport(std::move(R));
        // No need to continue for more gotos for this FreeSite; one is enough.
        break;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possible double free across replay/retry loop due to missing NULL reset",
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
