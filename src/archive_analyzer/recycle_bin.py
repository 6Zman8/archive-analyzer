"""Windows recycle operation with an explicit veto on permanent deletion."""
from pathlib import Path


def recycle_file(path: Path) -> None:
    import pythoncom
    import pywintypes
    from win32com.shell import shell, shellcon
    from win32com.server.exception import COMException
    from win32com.server.policy import DesignatedWrapPolicy

    class Sink(DesignatedWrapPolicy):
        _com_interfaces_ = [shell.IID_IFileOperationProgressSink]
        _public_methods_ = ["StartOperations", "FinishOperations", "PreRenameItem", "PostRenameItem",
                           "PreMoveItem", "PostMoveItem", "PreCopyItem", "PostCopyItem",
                           "PreDeleteItem", "PostDeleteItem", "PreNewItem", "PostNewItem",
                           "UpdateProgress", "ResetTimer", "PauseTimer", "ResumeTimer"]

        def __init__(self):
            self._wrap_(self)
            self.recycled = False

        def __getattr__(self, name):
            if name in self._public_methods_:
                return lambda *args: 0
            raise AttributeError(name)

        def PreDeleteItem(self, flags, item):
            if not flags & shellcon.TSF_DELETE_RECYCLE_IF_POSSIBLE:
                raise COMException("휴지통을 사용할 수 없습니다.", scode=-2147467260)
            return 0

        def PostDeleteItem(self, flags, item, result, newly_created):
            self.recycled = result >= 0 and newly_created is not None
            return 0

    pythoncom.CoInitialize()
    try:
        operation = pythoncom.CoCreateInstance(shell.CLSID_FileOperation, None,
                                               pythoncom.CLSCTX_ALL, shell.IID_IFileOperation)
        operation.SetOperationFlags(shellcon.FOF_SILENT | shellcon.FOF_NOCONFIRMATION
            | shellcon.FOF_NOERRORUI | shellcon.FOFX_EARLYFAILURE | 0x20000000 | 0x00080000)
        sink = Sink()
        operation.DeleteItem(shell.SHCreateItemFromParsingName(str(path.absolute()), None, shell.IID_IShellItem),
                             pythoncom.WrapObject(sink, shell.IID_IFileOperationProgressSink))
        result = operation.PerformOperations()
        if result or operation.GetAnyOperationsAborted() or not sink.recycled:
            raise OSError("휴지통 이동을 확인하지 못했습니다.")
    except pywintypes.com_error as error:
        raise OSError("휴지통 이동에 실패했습니다.") from error
    finally:
        pythoncom.CoUninitialize()
