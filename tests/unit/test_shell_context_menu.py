from pathlib import Path

import pytest

from archive_analyzer.shell_context_menu import show_shell_context_menu


def test_shell_context_menu_rejects_a_missing_file_before_calling_windows(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        show_shell_context_menu(tmp_path / "missing.cbz", 1, 10, 20)
