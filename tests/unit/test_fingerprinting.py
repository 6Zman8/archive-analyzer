import hashlib
import threading
import warnings
from io import BytesIO
from re import fullmatch

import pytest
from PIL import Image

import archive_analyzer.fingerprinting as fingerprinting
from archive_analyzer.fingerprinting import (
    FingerprintFailure,
    fingerprint_image,
    hamming_distance,
    probe_positions,
)
from tests.image_helpers import encoded_gradient


def _encode(image: Image.Image, format: str, **save_args: object) -> bytes:
    output = BytesIO()
    image.save(output, format=format, **save_args)
    return output.getvalue()


def _corrupt_exif_jpeg() -> bytes:
    payload = _encode(Image.new("RGB", (3, 2), "red"), "JPEG")
    exif = b"Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00"
    segment = b"\xff\xe1" + (len(exif) + 2).to_bytes(2, "big") + exif
    return payload[:2] + segment + payload[2:]


def test_probe_positions_are_unique_and_bounded() -> None:
    assert probe_positions(tuple(range(3))) == (0, 1, 2)
    assert probe_positions(tuple(range(100))) == (0, 10, 25, 50, 74, 89, 99)


def test_reencoded_image_keeps_close_perceptual_hash() -> None:
    original = encoded_gradient("PNG", size=(160, 240))
    reencoded = encoded_gradient("JPEG", size=(320, 480), quality=82)

    left = fingerprint_image(original)
    right = fingerprint_image(reencoded)

    assert left.pixel_sha256 != right.pixel_sha256
    assert hamming_distance(left.dhash64, right.dhash64) <= 6


def test_oversized_decoded_image_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fingerprinting, "MAX_IMAGE_PIXELS", 100)

    with pytest.raises(FingerprintFailure, match="IMAGE_PIXEL_LIMIT"):
        fingerprint_image(encoded_gradient("PNG", size=(11, 10)))


def test_pillow_bomb_warning_is_a_pixel_limit_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_bomb_warning(*_args: object, **_kwargs: object) -> None:
        fingerprinting.Image.warnings.warn(
            "image is too large", fingerprinting.Image.DecompressionBombWarning
        )

    monkeypatch.setattr(fingerprinting.Image, "open", raise_bomb_warning)

    with pytest.raises(FingerprintFailure, match="IMAGE_PIXEL_LIMIT"):
        fingerprint_image(b"small payload")


def test_byte_limit_accepts_exact_limit_and_rejects_limit_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = encoded_gradient("PNG", size=(16, 12))
    assert fingerprinting.MAX_IMAGE_BYTES == 128 * 1024 * 1024
    monkeypatch.setattr(fingerprinting, "MAX_IMAGE_BYTES", len(payload))

    fingerprint_image(payload)

    with pytest.raises(FingerprintFailure, match="IMAGE_BYTE_LIMIT") as raised:
        fingerprint_image(payload + b"x")

    assert raised.value.code == "IMAGE_BYTE_LIMIT"


def test_pixel_limit_accepts_exact_limit_and_rejects_limit_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = encoded_gradient("PNG", size=(11, 10))
    assert fingerprinting.MAX_IMAGE_PIXELS == 40_000_000
    monkeypatch.setattr(fingerprinting, "MAX_IMAGE_PIXELS", 110)

    fingerprint_image(payload)

    monkeypatch.setattr(fingerprinting, "MAX_IMAGE_PIXELS", 109)
    with pytest.raises(FingerprintFailure, match="IMAGE_PIXEL_LIMIT") as raised:
        fingerprint_image(payload)

    assert raised.value.code == "IMAGE_PIXEL_LIMIT"


@pytest.mark.parametrize(
    "truncated",
    (
        encoded_gradient("PNG", size=(60, 40))[:-10],
        encoded_gradient("JPEG", size=(60, 40))[:-1],
    ),
)
def test_truncated_images_are_rejected_after_verification_and_decode(truncated: bytes) -> None:
    with pytest.raises(FingerprintFailure, match="IMAGE_DECODE_FAILED") as raised:
        fingerprint_image(truncated)

    assert raised.value.code == "IMAGE_DECODE_FAILED"


def test_corrupt_exif_warning_is_a_decode_failure() -> None:
    with pytest.raises(FingerprintFailure, match="IMAGE_DECODE_FAILED") as raised:
        fingerprint_image(_corrupt_exif_jpeg())

    assert raised.value.code == "IMAGE_DECODE_FAILED"


def test_exif_orientation_is_applied() -> None:
    image = Image.new("RGB", (3, 2), "red")
    exif = Image.Exif()
    exif[274] = 6

    result = fingerprint_image(_encode(image, "JPEG", exif=exif))

    assert (result.width, result.height) == (2, 3)


def test_l_and_rgb_images_share_pixel_hash_but_not_byte_hash() -> None:
    grayscale = Image.new("L", (2, 2))
    grayscale.putdata((0, 64, 128, 255))
    l_payload = _encode(grayscale, "PNG")
    rgb_payload = _encode(grayscale.convert("RGB"), "PNG")

    left = fingerprint_image(l_payload)
    right = fingerprint_image(rgb_payload)

    assert fingerprint_image(l_payload) == left
    assert left.byte_sha256 == hashlib.sha256(l_payload).hexdigest()
    assert left.byte_sha256 != right.byte_sha256
    assert left.pixel_sha256 == right.pixel_sha256


def test_perceptual_hashes_are_lowercase_64_bit_hex_and_hamming_is_bounded() -> None:
    result = fingerprint_image(encoded_gradient("PNG", size=(16, 12)))

    assert all(
        fullmatch(r"[0-9a-f]{16}", value) is not None
        for value in (result.dhash64, result.ahash64)
    )
    assert hamming_distance("0" * 16, "0" * 16) == 0
    assert hamming_distance("0" * 16, "f" * 16) == 64


def test_warning_globals_are_unchanged_after_fingerprinting() -> None:
    before_filters = warnings.filters
    before_filter_values = before_filters[:]
    before_showwarning = warnings.showwarning

    fingerprint_image(encoded_gradient("PNG", size=(16, 12)))

    assert warnings.filters is before_filters
    assert warnings.filters == before_filter_values
    assert warnings.showwarning is before_showwarning


def test_concurrent_fingerprint_calls_are_serialized_and_succeed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_payload = encoded_gradient("PNG", size=(16, 12))
    second_payload = encoded_gradient("PNG", size=(17, 13))
    original_verify = fingerprinting._verify_image
    first_inside = threading.Event()
    second_started = threading.Event()
    second_inside = threading.Event()
    release_first = threading.Event()
    results: dict[bytes, fingerprinting.ImageFingerprint] = {}
    errors: list[BaseException] = []

    def controlled_verify(payload: bytes) -> None:
        if payload == first_payload:
            first_inside.set()
            assert release_first.wait(timeout=2)
        else:
            second_inside.set()
        original_verify(payload)

    def run(payload: bytes, started: threading.Event | None = None) -> None:
        if started is not None:
            started.set()
        try:
            results[payload] = fingerprint_image(payload)
        except BaseException as error:  # noqa: BLE001 - retain thread failure for the test
            errors.append(error)

    monkeypatch.setattr(fingerprinting, "_verify_image", controlled_verify)
    first = threading.Thread(target=run, args=(first_payload,))
    second = threading.Thread(target=run, args=(second_payload, second_started))
    first.start()
    assert first_inside.wait(timeout=1)
    second.start()
    assert second_started.wait(timeout=1)

    try:
        assert not second_inside.wait(timeout=0.2)
    finally:
        release_first.set()
        first.join(timeout=2)
        second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert second_inside.is_set()
    assert not errors
    assert (results[first_payload].width, results[first_payload].height) == (16, 12)
    assert (results[second_payload].width, results[second_payload].height) == (17, 13)


@pytest.mark.parametrize(("policy", "warning_is_error"), (("ignore", False), ("error", True)))
def test_external_userwarning_policy_and_globals_are_preserved_during_fingerprinting(
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
    warning_is_error: bool,
) -> None:
    payload = encoded_gradient("PNG", size=(16, 12))
    original_verify = fingerprinting._verify_image
    fingerprint_inside = threading.Event()
    release_fingerprint = threading.Event()
    fingerprint_errors: list[BaseException] = []
    warning_errors: list[BaseException] = []

    def controlled_verify(value: bytes) -> None:
        fingerprint_inside.set()
        assert release_fingerprint.wait(timeout=2)
        original_verify(value)

    def run_fingerprint() -> None:
        try:
            fingerprint_image(payload)
        except BaseException as error:  # noqa: BLE001 - retain thread failure for the test
            fingerprint_errors.append(error)

    def emit_external_warning() -> None:
        try:
            fingerprinting.Image.warnings.warn("external warning", UserWarning)
        except BaseException as error:  # noqa: BLE001 - inspect configured warning behavior
            warning_errors.append(error)

    monkeypatch.setattr(fingerprinting, "_verify_image", controlled_verify)
    with warnings.catch_warnings():
        warnings.simplefilter(policy, UserWarning)
        before_filters = warnings.filters
        before_filter_values = before_filters[:]
        before_showwarning = warnings.showwarning
        fingerprint_thread = threading.Thread(target=run_fingerprint)
        fingerprint_thread.start()
        assert fingerprint_inside.wait(timeout=1)

        warning_thread = threading.Thread(target=emit_external_warning)
        warning_thread.start()
        warning_thread.join(timeout=1)
        filters_unchanged_during = (
            warnings.filters is before_filters and warnings.filters == before_filter_values
        )
        showwarning_unchanged_during = warnings.showwarning is before_showwarning

        release_fingerprint.set()
        fingerprint_thread.join(timeout=2)

        assert not warning_thread.is_alive()
        assert not fingerprint_thread.is_alive()
        assert not fingerprint_errors
        assert (len(warning_errors) == 1) is warning_is_error
        if warning_is_error:
            assert isinstance(warning_errors[0], UserWarning)
        assert filters_unchanged_during
        assert showwarning_unchanged_during
        assert warnings.filters is before_filters
        assert warnings.filters == before_filter_values
        assert warnings.showwarning is before_showwarning


def test_dhash_exact_value_uses_left_to_right_row_major_bits() -> None:
    pixels = bytes((x * 23 + y * 31 + x * y * 7) % 256 for y in range(8) for x in range(9))
    result = fingerprint_image(_encode(Image.frombytes("L", (9, 8), pixels), "PNG"))

    assert result.dhash64 == "0001041021424489"


def test_ahash_exact_value_includes_pixels_equal_to_the_average() -> None:
    values = tuple(
        0 if (index * 17) % 64 < 20 else 64 if (index * 17) % 64 < 44 else 128
        for index in range(64)
    )
    result = fingerprint_image(_encode(Image.frombytes("L", (8, 8), bytes(values)), "PNG"))

    assert sum(values) / len(values) == 64
    assert values.count(64) == 24
    assert result.ahash64 == "37776eeecddd9bbb"


def test_pixel_sha256_uses_big_endian_size_prefix_and_rgb_bytes() -> None:
    rgb_bytes = bytes((17, 3, 251, 0, 128, 64, 255, 1, 9, 45, 199, 80, 7, 222, 19, 111, 5, 240))
    image = Image.frombytes("RGB", (3, 2), rgb_bytes)
    result = fingerprint_image(_encode(image, "PNG"))
    expected = hashlib.sha256(
        (3).to_bytes(4, "big") + (2).to_bytes(4, "big") + rgb_bytes
    ).hexdigest()

    assert result.pixel_sha256 == expected


def test_lossless_exif_orientation_has_expected_pixel_sha256() -> None:
    source = Image.frombytes(
        "RGB",
        (3, 2),
        bytes((17, 3, 251, 0, 128, 64, 255, 1, 9, 45, 199, 80, 7, 222, 19, 111, 5, 240)),
    )
    exif = Image.Exif()
    exif[274] = 6
    result = fingerprint_image(_encode(source, "PNG", exif=exif))
    expected_image = source.transpose(Image.Transpose.ROTATE_270)
    expected = hashlib.sha256(
        expected_image.width.to_bytes(4, "big")
        + expected_image.height.to_bytes(4, "big")
        + expected_image.tobytes()
    ).hexdigest()

    assert (result.width, result.height) == (2, 3)
    assert result.pixel_sha256 == expected
