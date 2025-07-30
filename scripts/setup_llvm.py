import subprocess as sp
from pathlib import Path

from fire import Fire
from loguru import logger


def setup_llvm(llvm_dir_str: str):
    llvm_dir = Path(llvm_dir_str)
    if not llvm_dir.exists():
        logger.error(f"LLVM directory {llvm_dir} does not exist.")

        # Download the zip file
        zip_filename = "llvmorg-18.1.8.zip"
        zip_path = llvm_dir.parent / zip_filename

        logger.info("Downloading LLVM source...")
        sp.run(
            [
                "wget",
                "https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-18.1.8.zip",
                "-O",
                str(zip_path),
            ],
            cwd=llvm_dir.parent,
            check=True,
        )

        logger.info("Extracting LLVM source...")
        # Extract the zip file - this creates llvm-project-llvmorg-18.1.8/
        sp.run(["unzip", str(zip_path)], cwd=llvm_dir.parent, check=True)

        # Rename the extracted directory to the desired llvm_dir name
        extracted_dir = llvm_dir.parent / "llvm-project-llvmorg-18.1.8"
        if extracted_dir.exists():
            extracted_dir.rename(llvm_dir)

        # Delete the zip file
        logger.info("Cleaning up zip file...")
        zip_path.unlink()

    llvm_abs_dir = llvm_dir.resolve()

    # Prepare the plugin files
    logger.info("Copying plugin files...")
    # cp llvm_utils/create_plugin.py $LLVM_DIR/clang/lib/Analysis/plugins/
    sp.run(
        [
            "cp",
            "llvm_utils/create_plugin.py",
            f"{llvm_abs_dir}/clang/lib/Analysis/plugins/",
        ]
    )
    plugin_work_dir = llvm_dir / "clang" / "lib" / "Analysis" / "plugins"
    # python3 ./create_plugin.py SAGenTest
    sp.run(["python3", "create_plugin.py", "SAGenTest"], cwd=plugin_work_dir.absolute())

    # Prepare utility functions
    logger.info("Copying utility functions...")
    # cp llvm_utils/utility.cpp $LLVM_DIR/clang/lib/StaticAnalyzer/Checkers/
    # cp llvm_utils/utility.h $LLVM_DIR/clang/include/clang/StaticAnalyzer/Checkers/
    sp.run(
        [
            "cp",
            "llvm_utils/utility.cpp",
            f"{llvm_abs_dir}/clang/lib/StaticAnalyzer/Checkers/",
        ]
    )
    sp.run(
        [
            "cp",
            "llvm_utils/utility.h",
            f"{llvm_abs_dir}/clang/include/clang/StaticAnalyzer/Checkers/",
        ]
    )

    cmakefile = (
        llvm_dir / "clang" / "lib" / "StaticAnalyzer" / "Checkers" / "CMakeLists.txt"
    )
    new_cmakefile_content = """\
set(LLVM_LINK_COMPONENTS
  FrontendOpenMP
  Support
  TargetParser
  )

add_clang_library(clangStaticAnalyzerCheckers
  AnalysisOrderChecker.cpp
  AnalyzerStatsChecker.cpp
  ArrayBoundChecker.cpp
  ArrayBoundCheckerV2.cpp
  BasicObjCFoundationChecks.cpp
  BitwiseShiftChecker.cpp
  BlockInCriticalSectionChecker.cpp
  BoolAssignmentChecker.cpp
  BuiltinFunctionChecker.cpp
  CStringChecker.cpp
  CStringSyntaxChecker.cpp
  CallAndMessageChecker.cpp
  CastSizeChecker.cpp
  CastToStructChecker.cpp
  CastValueChecker.cpp
  CheckObjCDealloc.cpp
  CheckObjCInstMethSignature.cpp
  CheckPlacementNew.cpp
  CheckSecuritySyntaxOnly.cpp
  CheckSizeofPointer.cpp
  CheckerDocumentation.cpp
  ChrootChecker.cpp
  CloneChecker.cpp
  ContainerModeling.cpp
  ConversionChecker.cpp
  CXXDeleteChecker.cpp
  CXXSelfAssignmentChecker.cpp
  DeadStoresChecker.cpp
  DebugCheckers.cpp
  DebugContainerModeling.cpp
  DebugIteratorModeling.cpp
  DereferenceChecker.cpp
  DirectIvarAssignment.cpp
  DivZeroChecker.cpp
  DynamicTypePropagation.cpp
  DynamicTypeChecker.cpp
  EnumCastOutOfRangeChecker.cpp
  ErrnoChecker.cpp
  ErrnoModeling.cpp
  ErrnoTesterChecker.cpp
  ExprInspectionChecker.cpp
  FixedAddressChecker.cpp
  FuchsiaHandleChecker.cpp
  GCDAntipatternChecker.cpp
  GenericTaintChecker.cpp
  GTestChecker.cpp
  IdenticalExprChecker.cpp
  InnerPointerChecker.cpp
  InvalidatedIteratorChecker.cpp
  cert/InvalidPtrChecker.cpp
  Iterator.cpp
  IteratorModeling.cpp
  IteratorRangeChecker.cpp
  IvarInvalidationChecker.cpp
  LLVMConventionsChecker.cpp
  LocalizationChecker.cpp
  MacOSKeychainAPIChecker.cpp
  MacOSXAPIChecker.cpp
  MallocChecker.cpp
  MallocOverflowSecurityChecker.cpp
  MallocSizeofChecker.cpp
  MismatchedIteratorChecker.cpp
  MmapWriteExecChecker.cpp
  MIGChecker.cpp
  MoveChecker.cpp
  MPI-Checker/MPIBugReporter.cpp
  MPI-Checker/MPIChecker.cpp
  MPI-Checker/MPIFunctionClassifier.cpp
  NSAutoreleasePoolChecker.cpp
  NSErrorChecker.cpp
  NoReturnFunctionChecker.cpp
  NonNullParamChecker.cpp
  NonnullGlobalConstantsChecker.cpp
  NullabilityChecker.cpp
  NumberObjectConversionChecker.cpp
  ObjCAtSyncChecker.cpp
  ObjCAutoreleaseWriteChecker.cpp
  ObjCContainersASTChecker.cpp
  ObjCContainersChecker.cpp
  ObjCMissingSuperCallChecker.cpp
  ObjCPropertyChecker.cpp
  ObjCSelfInitChecker.cpp
  ObjCSuperDeallocChecker.cpp
  ObjCUnusedIVarsChecker.cpp
  OSObjectCStyleCast.cpp
  PaddingChecker.cpp
  PointerArithChecker.cpp
  PointerIterationChecker.cpp
  PointerSortingChecker.cpp
  PointerSubChecker.cpp
  PthreadLockChecker.cpp
  cert/PutenvWithAutoChecker.cpp
  RetainCountChecker/RetainCountChecker.cpp
  RetainCountChecker/RetainCountDiagnostics.cpp
  ReturnPointerRangeChecker.cpp
  ReturnUndefChecker.cpp
  ReturnValueChecker.cpp
  RunLoopAutoreleaseLeakChecker.cpp
  SimpleStreamChecker.cpp
  SmartPtrChecker.cpp
  SmartPtrModeling.cpp
  StackAddrEscapeChecker.cpp
  StdLibraryFunctionsChecker.cpp
  StdVariantChecker.cpp
  STLAlgorithmModeling.cpp
  StreamChecker.cpp
  StringChecker.cpp
  Taint.cpp
  TaintTesterChecker.cpp
  TestAfterDivZeroChecker.cpp
  TraversalChecker.cpp
  TrustNonnullChecker.cpp
  TrustReturnsNonnullChecker.cpp
  UndefBranchChecker.cpp
  UndefCapturedBlockVarChecker.cpp
  UndefResultChecker.cpp
  UndefinedArraySubscriptChecker.cpp
  UndefinedAssignmentChecker.cpp
  UndefinedNewArraySizeChecker.cpp
  UninitializedObject/UninitializedObjectChecker.cpp
  UninitializedObject/UninitializedPointee.cpp
  UnixAPIChecker.cpp
  UnreachableCodeChecker.cpp
  VforkChecker.cpp
  VLASizeChecker.cpp
  ValistChecker.cpp
  VirtualCallChecker.cpp
  WebKit/NoUncountedMembersChecker.cpp
  WebKit/ASTUtils.cpp
  WebKit/PtrTypesSemantics.cpp
  WebKit/RefCntblBaseVirtualDtorChecker.cpp
  WebKit/UncountedCallArgsChecker.cpp
  WebKit/UncountedLambdaCapturesChecker.cpp
  WebKit/UncountedLocalVarsChecker.cpp
  utility.cpp

  LINK_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangLex
  clangStaticAnalyzerCore

  DEPENDS
  omp_gen
  ClangDriverOptions
  )
"""
    cmakefile.write_text(new_cmakefile_content)

    # Build the LLVM
    logger.info("Building LLVM...")
    # mkdir -p $LLVM_DIR/build
    build_dir = llvm_dir / "build"
    # Delete the build directory if it exists
    if build_dir.exists():
        sp.run(["rm", "-rf", build_dir])
    build_dir.mkdir()

    # cmake
    # cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm
    res = sp.run(
        'cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm',
        cwd=build_dir,
        shell=True,
    )
    if res.returncode != 0:
        logger.error("CMake failed.")
        return

    # make
    make_res = sp.run("make -j32", cwd=build_dir, shell=True)
    if make_res.returncode != 0:
        logger.error("Make failed.")
        return

    make_res = sp.run("make SAGenTestPlugin -j32", cwd=build_dir, shell=True)
    if make_res.returncode != 0:
        logger.error("Make failed.")
        return
    logger.success("LLVM setup completed.")


if __name__ == "__main__":
    Fire(setup_llvm)
