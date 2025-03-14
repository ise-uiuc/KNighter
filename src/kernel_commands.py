args = [
    ("-disable-checker", "core"),
    ("-disable-checker", "cplusplus"),
    ("-disable-checker", "deadcode"),
    ("-disable-checker", "unix"),
    ("-disable-checker", "nullability"),
    ("-disable-checker", "security"),
    ("-maxloop", 4),
    ("-o", "tmp/SAGenTestCSAResult"),
]


def generate_command(llvm_build_dir: str, no_output=False, plugin_names=None) -> str:
    comd = f"PATH={llvm_build_dir}/bin:$PATH "
    comd += f"{llvm_build_dir}/bin/scan-build --use-cc=clang "
    if plugin_names:
        for plugin_name in plugin_names:
            comd += f"-load-plugin {llvm_build_dir}/lib/{plugin_name}Plugin.so "
            comd += f"-enable-checker custom.{plugin_name}Checker "
    else:
        comd += f"-load-plugin {llvm_build_dir}/lib/SAGenTestPlugin.so "
        comd += "-enable-checker custom.SAGenTestChecker "
    for arg_name, arg_value in args:
        if no_output and arg_name == "-o":
            continue
        comd += f"{arg_name} {arg_value} "
    return comd


def generate_command_file(file: str, llvm_build_dir: str) -> str:
    comd = generate_command(llvm_build_dir)
    comd += f"clang {file} -o tmp/SAGenTest.out"
    return comd


def generate_command_obj(obj: str, llvm_build_dir: str) -> str:
    comd = generate_command(llvm_build_dir)
    comd += f"make LLVM=1 ARCH=x86 {obj} -j32"
