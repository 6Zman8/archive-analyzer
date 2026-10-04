"""Python 3.13.15 reports the ZIP64 EOCD's own location, unlike 3.13.3."""
import zipfile

import pytest

from archive_analyzer.inspection import zip_backend
from archive_analyzer.inspection.base import InspectionFailure


@pytest.mark.parametrize("prefix", [b"", b"MZself-extracting-prefix"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_new_end_record_location_supports_zip64(tmp_path, monkeypatch, prefix, over_limit):
    path = tmp_path / "fixture.zip"
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(3):
            archive.writestr(f"{index}.jpg", b"fixture")
    path.write_bytes(prefix + path.read_bytes())
    original = zipfile._EndRecData
    def new_location(stream):
        record = original(stream)
        stream.seek(0)
        record[zipfile._ECD_LOCATION] = stream.read().rindex(zipfile.stringEndArchive64)
        return record
    monkeypatch.setattr(zipfile, "_EndRecData", new_location)
    monkeypatch.setattr(zip_backend, "MAX_ARCHIVE_ENTRIES", 2 if over_limit else 10)
    if over_limit:
        with pytest.raises(InspectionFailure) as error:
            zip_backend._preflight_central_directory(path)
        assert error.value.code == "ARCHIVE_LIMIT_EXCEEDED"
    else:
        zip_backend._preflight_central_directory(path)
