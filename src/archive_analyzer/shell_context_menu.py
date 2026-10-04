from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from uuid import UUID

from ctypes import wintypes


_CMF_EXPLORE = 0x00000004
_COMMAND_FIRST = 1
_COMMAND_LAST = 0x7FFF
_TPM_RIGHTBUTTON = 0x0002
_TPM_RETURNCMD = 0x0100
_SW_SHOWNORMAL = 1
_WM_NULL = 0x0000
_RPC_E_CHANGED_MODE = -2147417850


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def from_text(cls, value: str) -> _GUID:
        raw = UUID(value).bytes_le
        return cls(
            int.from_bytes(raw[0:4], "little"),
            int.from_bytes(raw[4:6], "little"),
            int.from_bytes(raw[6:8], "little"),
            (ctypes.c_ubyte * 8).from_buffer_copy(raw[8:16]),
        )


class _CMINVOKECOMMANDINFO(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.DWORD),
        ("hwnd", wintypes.HWND),
        ("lpVerb", ctypes.c_void_p),
        ("lpParameters", ctypes.c_void_p),
        ("lpDirectory", ctypes.c_void_p),
        ("nShow", ctypes.c_int),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
    )


_IID_ISHELLFOLDER = _GUID.from_text("000214E6-0000-0000-C000-000000000046")
_IID_ICONTEXTMENU = _GUID.from_text("000214E4-0000-0000-C000-000000000046")


def show_shell_context_menu(path: Path, owner_hwnd: int, x: int, y: int) -> bool:
    """Show the file's native Windows shell context menu at screen coordinates."""

    selected = Path(path)
    if not selected.is_file():
        raise FileNotFoundError(selected)
    if sys.platform != "win32":
        raise OSError("Windows shell context menus are unavailable.")

    ole32 = ctypes.OleDLL("ole32")
    shell32 = ctypes.OleDLL("shell32")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    ole32.CoInitialize.argtypes = (ctypes.c_void_p,)
    ole32.CoInitialize.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    ole32.CoTaskMemFree.restype = None
    shell32.SHParseDisplayName.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    shell32.SHParseDisplayName.restype = ctypes.c_long
    shell32.SHBindToParent.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_GUID),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    shell32.SHBindToParent.restype = ctypes.c_long
    user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.TrackPopupMenuEx.argtypes = (
        ctypes.c_void_p,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        ctypes.c_void_p,
    )
    user32.DestroyMenu.argtypes = (ctypes.c_void_p,)
    user32.DestroyMenu.restype = wintypes.BOOL
    user32.PostMessageW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )
    user32.PostMessageW.restype = wintypes.BOOL
    initialized = False
    pidl = ctypes.c_void_p()
    parent = ctypes.c_void_p()
    child = ctypes.c_void_p()
    context = ctypes.c_void_p()
    menu = ctypes.c_void_p()
    try:
        result = int(ole32.CoInitialize(None))
        if result < 0 and result != _RPC_E_CHANGED_MODE:
            _raise_hresult("CoInitialize", result)
        initialized = result >= 0

        attributes = wintypes.DWORD()
        result = int(
            shell32.SHParseDisplayName(
                str(selected.resolve(strict=True)),
                None,
                ctypes.byref(pidl),
                0,
                ctypes.byref(attributes),
            )
        )
        _check_hresult("SHParseDisplayName", result)
        result = int(
            shell32.SHBindToParent(
                pidl,
                ctypes.byref(_IID_ISHELLFOLDER),
                ctypes.byref(parent),
                ctypes.byref(child),
            )
        )
        _check_hresult("SHBindToParent", result)

        children = (ctypes.c_void_p * 1)(child.value)
        get_ui_object = _com_method(
            parent,
            10,
            ctypes.c_long,
            wintypes.HWND,
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(_GUID),
            ctypes.POINTER(wintypes.UINT),
            ctypes.POINTER(ctypes.c_void_p),
        )
        result = int(
            get_ui_object(
                parent,
                wintypes.HWND(owner_hwnd),
                1,
                children,
                ctypes.byref(_IID_ICONTEXTMENU),
                None,
                ctypes.byref(context),
            )
        )
        _check_hresult("IShellFolder.GetUIObjectOf", result)

        user32.CreatePopupMenu.restype = ctypes.c_void_p
        menu = ctypes.c_void_p(user32.CreatePopupMenu())
        if not menu.value:
            raise ctypes.WinError(ctypes.get_last_error())
        query_menu = _com_method(
            context,
            3,
            ctypes.c_long,
            ctypes.c_void_p,
            wintypes.UINT,
            wintypes.UINT,
            wintypes.UINT,
            wintypes.UINT,
        )
        result = int(
            query_menu(
                context,
                menu,
                0,
                _COMMAND_FIRST,
                _COMMAND_LAST,
                _CMF_EXPLORE,
            )
        )
        _check_hresult("IContextMenu.QueryContextMenu", result)

        user32.SetForegroundWindow(wintypes.HWND(owner_hwnd))
        user32.TrackPopupMenuEx.restype = wintypes.UINT
        command = int(
            user32.TrackPopupMenuEx(
                menu,
                _TPM_RIGHTBUTTON | _TPM_RETURNCMD,
                int(x),
                int(y),
                wintypes.HWND(owner_hwnd),
                None,
            )
        )
        if command == 0:
            return False

        invoke = _com_method(
            context,
            4,
            ctypes.c_long,
            ctypes.POINTER(_CMINVOKECOMMANDINFO),
        )
        info = _CMINVOKECOMMANDINFO(
            cbSize=ctypes.sizeof(_CMINVOKECOMMANDINFO),
            fMask=0,
            hwnd=wintypes.HWND(owner_hwnd),
            lpVerb=ctypes.c_void_p(command - _COMMAND_FIRST),
            lpParameters=None,
            lpDirectory=None,
            nShow=_SW_SHOWNORMAL,
            dwHotKey=0,
            hIcon=None,
        )
        result = int(invoke(context, ctypes.byref(info)))
        _check_hresult("IContextMenu.InvokeCommand", result)
        return True
    finally:
        if owner_hwnd:
            user32.PostMessageW(wintypes.HWND(owner_hwnd), _WM_NULL, 0, 0)
        if menu.value:
            user32.DestroyMenu(menu)
        _release(context)
        _release(parent)
        if pidl.value:
            ole32.CoTaskMemFree(pidl)
        if initialized:
            ole32.CoUninitialize()


def _com_method(
    pointer: ctypes.c_void_p,
    index: int,
    result_type,
    *argument_types,
):  # type: ignore[no-untyped-def]
    table = ctypes.cast(
        pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
    ).contents
    prototype = ctypes.WINFUNCTYPE(
        result_type, ctypes.c_void_p, *argument_types
    )
    return prototype(table[index])


def _release(pointer: ctypes.c_void_p) -> None:
    if pointer.value:
        release = _com_method(pointer, 2, wintypes.ULONG)
        release(pointer)


def _check_hresult(operation: str, result: int) -> None:
    if result < 0:
        _raise_hresult(operation, result)


def _raise_hresult(operation: str, result: int) -> None:
    raise OSError(f"{operation} failed with HRESULT 0x{result & 0xFFFFFFFF:08X}")


__all__ = ["show_shell_context_menu"]
