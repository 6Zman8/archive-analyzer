"""Keep dialogs owned by, and on the monitor of, the active review window."""
from functools import partial


class OwnedDialogs:
    def __init__(self, module, parent):
        self.module = module
        self.parent = parent

    def __getattr__(self, name):
        return partial(getattr(self.module, name), parent=self.parent)


def center_dialog(dialog, parent):
    parent = parent.winfo_toplevel()
    dialog.transient(parent)
    dialog.update_idletasks()
    width = max(dialog.winfo_width(), dialog.winfo_reqwidth())
    height = max(dialog.winfo_height(), dialog.winfo_reqheight())
    x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
    try:
        import win32api
        import win32gui
        from win32con import MONITOR_DEFAULTTONEAREST, SWP_NOSIZE, SWP_NOZORDER, SWP_NOACTIVATE
        monitor = win32api.MonitorFromWindow(parent.winfo_id(), MONITOR_DEFAULTTONEAREST)
        left, top, right, bottom = win32api.GetMonitorInfo(monitor)['Work']
        x = max(left, min(x, right - width))
        y = max(top, min(y, bottom - height))
        # Tk's Windows geometry handling may clamp negative monitor coordinates
        # back to (0, 0). Position its native wrapper directly without activation.
        handle = win32gui.GetParent(dialog.winfo_id()) or dialog.winfo_id()
        win32gui.SetWindowPos(handle, 0, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
    except ImportError:
        dialog.geometry(f'+{x}+{y}')
