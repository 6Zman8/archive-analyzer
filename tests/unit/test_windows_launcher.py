import io
from types import SimpleNamespace

from tools import windows_launcher


def test_windowed_output_accepts_korean_on_english_windows(monkeypatch):
    buffer = io.BytesIO()
    output = io.TextIOWrapper(buffer, encoding="cp1252")
    monkeypatch.setattr(windows_launcher, "sys", SimpleNamespace(stdout=output, stderr=None))
    windows_launcher.configure_output()
    output.write("한글 경로 / 日本語 / 中文")
    output.flush()
    assert buffer.getvalue().decode("utf-8") == "한글 경로 / 日本語 / 中文"
    windows_launcher.sys.stderr.write("검사 완료")
    windows_launcher.sys.stderr.close()

