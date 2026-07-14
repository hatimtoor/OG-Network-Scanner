# PyInstaller spec for a one-file NetScope.exe (Windows).
#   Build:  powershell -File scripts\build-exe.ps1
#   Output: dist\netscope.exe
#
# Bundles the web dashboard assets and the harder-to-detect dynamic imports
# (uvicorn workers, scapy layers). The MAC OUI DB downloads on first run.
from PyInstaller.utils.hooks import collect_submodules

datas = [("netscope/web", "netscope/web")]

hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("scapy.layers")
    + [
        "duckdb",
        "sqlmodel",
        "zeroconf",
        "psutil",
        "mac_vendor_lookup",
    ]
)

a = Analysis(
    ["netscope/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="netscope",
    console=True,
    upx=True,
    disable_windowed_traceback=False,
)
