from __future__ import annotations

import io

import pytest

from riec_guard.domain.normalize import MIB, UploadLimits, normalize_csv_upload
from riec_guard.errors import ApplicationError, ErrorCode


def _assert_error(
    expected_code: ErrorCode,
    payload: bytes,
    *,
    display_name: str = "measurements.csv",
    media_type: str | None = "text/csv",
    limits: UploadLimits | None = None,
) -> ApplicationError:
    with pytest.raises(ApplicationError) as exc_info:
        normalize_csv_upload(
            payload,
            display_name=display_name,
            media_type=media_type,
            limits=limits or UploadLimits(),
        )
    assert exc_info.value.code is expected_code
    return exc_info.value


def test_frozen_public_upload_limits():
    assert UploadLimits() == UploadLimits(
        max_file_size_bytes=10 * MIB,
        max_data_rows=100_000,
        max_columns=100,
        max_display_name_length=255,
    )


def test_file_size_boundary_is_inclusive_and_injectable():
    payload = b"a,b\n1,2\n"
    accepted = normalize_csv_upload(
        payload,
        display_name="boundary.csv",
        media_type="text/csv; charset=utf-8",
        limits=UploadLimits(max_file_size_bytes=len(payload)),
    )
    assert accepted.raw_bytes == payload

    _assert_error(
        ErrorCode.UPLOAD_TOO_LARGE,
        payload + b" ",
        limits=UploadLimits(max_file_size_bytes=len(payload)),
    )


def test_oversized_stream_is_rejected_after_only_limit_plus_one_bytes() -> None:
    class RecordingStream(io.BytesIO):
        requested_sizes: list[int | None]

        def __init__(self, data: bytes) -> None:
            super().__init__(data)
            self.requested_sizes = []

        def read(self, size: int | None = -1) -> bytes:
            self.requested_sizes.append(size)
            return super().read(size)

    stream = RecordingStream(b"a\n" + b"1" * 100)
    with pytest.raises(ApplicationError) as exc_info:
        normalize_csv_upload(
            stream,
            display_name="large.csv",
            media_type="text/csv",
            limits=UploadLimits(max_file_size_bytes=16),
        )
    assert exc_info.value.code is ErrorCode.UPLOAD_TOO_LARGE
    assert stream.tell() == 17
    assert stream.requested_sizes == [17]


def test_more_than_default_100000_data_rows_is_rejected():
    payload = b"quantity\n" + b"1\n" * 100_001
    _assert_error(ErrorCode.TOO_MANY_ROWS, payload)


def test_more_than_default_100_columns_is_rejected():
    header = ",".join(f"c{index}" for index in range(101))
    row = ",".join("1" for _ in range(101))
    _assert_error(ErrorCode.TOO_MANY_COLUMNS, f"{header}\n{row}\n".encode())


@pytest.mark.parametrize("display_name", ["data.txt", "data.xlsx", "data.pdf", "data.sqlite"])
def test_unsupported_extension_is_rejected(display_name: str):
    _assert_error(
        ErrorCode.UNSUPPORTED_FILE_TYPE,
        b"a,b\n1,2\n",
        display_name=display_name,
    )


@pytest.mark.parametrize("display_name", ["data.zip", "data.tar", "data.gz", "data.7z"])
def test_archive_extension_is_rejected(display_name: str):
    _assert_error(
        ErrorCode.ARCHIVE_UPLOAD_REJECTED,
        b"a,b\n1,2\n",
        display_name=display_name,
    )


def test_extension_and_content_type_mismatch_is_rejected():
    _assert_error(
        ErrorCode.UNSUPPORTED_FILE_TYPE,
        b"a,b\n1,2\n",
        media_type="application/pdf",
    )


@pytest.mark.parametrize(
    "signature",
    [
        b"PK\x03\x04payload",
        b"\x1f\x8bpayload",
        b"7z\xbc\xaf\x27\x1cpayload",
        b"Rar!\x1a\x07payload",
    ],
)
def test_archive_signatures_are_rejected_even_with_csv_name(signature: bytes):
    _assert_error(ErrorCode.ARCHIVE_UPLOAD_REJECTED, signature)


@pytest.mark.parametrize(
    "payload",
    [
        b"a,b\n1,\x00\n",
        b"a,b\n\xff,2\n",
        b"a,b\n1,\x01\n",
    ],
)
def test_nul_binary_and_unknown_encoding_are_rejected(payload: bytes):
    _assert_error(ErrorCode.BINARY_OR_NUL_CONTENT, payload)


@pytest.mark.parametrize(
    "signature",
    [
        b"%PDF-1.7",
        b"#!/bin/sh\nprintf unsafe\n",
        b"MZpayload",
        b"SQLite format 3\x00payload",
    ],
)
def test_non_csv_signatures_are_rejected(signature: bytes):
    _assert_error(ErrorCode.UNSUPPORTED_FILE_TYPE, signature)


def test_malformed_csv_returns_stable_structured_error():
    error = _assert_error(ErrorCode.MALFORMED_CSV, b'a,b\n"unterminated,2\n')
    assert error.to_envelope().code == "malformed_csv"
    assert error.to_envelope().details == {"field": "upload"}


@pytest.mark.parametrize(
    "display_name",
    [
        "../secret.csv",
        "..\\secret.csv",
        "/tmp/secret.csv",
        "C:\\temp\\secret.csv",
        "\\\\server\\share\\secret.csv",
        "\\\\.\\C:\\secret.csv",
        "subdir/secret.csv",
        "CON.csv",
        "LPT1.csv",
        "secret.csv.",
        "bad\x00.csv",
        "bad\n.csv",
        "Ｆ.csv",
    ],
)
def test_unsafe_display_filenames_are_rejected(display_name: str):
    _assert_error(
        ErrorCode.UNSAFE_DISPLAY_FILENAME,
        b"a,b\n1,2\n",
        display_name=display_name,
    )


def test_excessively_long_display_filename_is_rejected():
    _assert_error(
        ErrorCode.UNSAFE_DISPLAY_FILENAME,
        b"a,b\n1,2\n",
        display_name=f"{'a' * 252}.csv",
    )


def test_utf8_bom_is_removed_only_from_normalized_csv():
    payload = b"\xef\xbb\xbfquantity,group\n1,A\n"
    result = normalize_csv_upload(
        payload,
        display_name="bom.csv",
        media_type="text/csv",
        limits=UploadLimits(),
    )
    assert result.raw_bytes == payload
    assert result.normalized_bytes == b"quantity,group\n1,A\n"


def test_formula_and_shell_like_cells_remain_inert_data():
    payload = b'quantity,note\n1,"=2+2"\n2,"$(touch nope)"\n'
    result = normalize_csv_upload(
        payload,
        display_name="cells.csv",
        media_type="text/csv",
        limits=UploadLimits(),
    )
    assert b"=2+2" in result.normalized_bytes
    assert b"$(touch nope)" in result.normalized_bytes


def test_public_error_does_not_echo_absolute_filename_or_row_content():
    display_name = "/Users/example/secret.csv"
    row_content = "highly-sensitive-row-value"
    error = _assert_error(
        ErrorCode.UNSAFE_DISPLAY_FILENAME,
        f"a\n{row_content}\n".encode(),
        display_name=display_name,
    )
    public_text = f"{error} {error.to_envelope()}"
    assert display_name not in public_text
    assert row_content not in public_text
    assert "/Users/" not in public_text
