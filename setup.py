import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but some modules need manual configuration
build_exe_options = {
    "packages": ["os", "psutil", "PyQt5"],
    "excludes": [],
    "include_files": [],
    "include_msvcr": True,
}

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name = "ProcessManagerGUI",
    version = "1.0",
    description = "Professional Process Manager GUI",
    options = {"build_exe": build_exe_options},
    executables = [Executable("process_manager_gui.py", base=base)]
)
