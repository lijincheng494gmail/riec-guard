from __future__ import annotations

import csv
import io
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import BinaryIO

from riec_guard.errors import ApplicationError, ErrorCode

MIB = 1024 * 1024

_ACCEPTED_MEDIA_TYPES = frozenset({"text/csv", "application/csv"})
_ARCHIVE_SUFFIXES = frozenset(
    {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
)
_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)
_WINDOWS_DEVICE_PREFIXES = ("\\\\.\\", "\\\\?\\")
_WINDOWS_DRIVE_PATTERN = re.compile(r"\A[A-Za-z]:")


@dataclass(frozen=True, slots=True)
class UploadLimits:
    """Injectable public-demo limits used without global process mutation."""

    max_file_size_bytes: int = 10 * MIB
    max_data_rows: int = 100_000
    max_columns: int = 100
    max_display_name_length: int = 255

    def __post_init__(self) -> None:
        for field_name in (
            "max_file_size_bytes",
            "max_data_rows",
            "max_columns",
            "max_display_name_length",
        ):
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} must be positive")


@dataclass(frozen=True, slots=True)
class NormalizedCsv:
    raw_bytes: bytes
    normalized_bytes: bytes
    display_name: str
    media_type: str | None
    data_row_count: int
    column_count: int


def validate_display_filename(display_name: str, *, limits: UploadLimits) -> str:
    """Return a safe metadata-only name or reject path/device/normalization tricks."""

    if not isinstance(display_name, str) or not display_name:
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename is unsafe.",
            field="display_name",
        )
    if len(display_name) > limits.max_display_name_length:
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename is too long.",
            field="display_name",
        )
    if any(character == "\x00" or unicodedata.category(character) == "Cc" for character in display_name):
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename contains control characters.",
            field="display_name",
        )
    if unicodedata.normalize("NFKC", display_name) != display_name:
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename uses unsafe normalization.",
            field="display_name",
        )

    windows_path = PureWindowsPath(display_name)
    posix_path = PurePosixPath(display_name)
    if (
        "/" in display_name
        or "\\" in display_name
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or display_name.startswith(_WINDOWS_DEVICE_PREFIXES)
        or _WINDOWS_DRIVE_PATTERN.match(display_name)
        or display_name in {".", ".."}
    ):
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename must be a plain filename.",
            field="display_name",
        )

    stem = display_name.rsplit(".", 1)[0].rstrip(" .").upper()
    if stem in _DEVICE_NAMES or display_name.rstrip(" .") != display_name:
        raise _upload_error(
            ErrorCode.UNSAFE_DISPLAY_FILENAME,
            "The upload display filename is reserved or unsafe.",
            field="display_name",
        )

    suffix = PurePosixPath(display_name).suffix.lower()
    if suffix in _ARCHIVE_SUFFIXES:
        raise _upload_error(
            ErrorCode.ARCHIVE_UPLOAD_REJECTED,
            "Archive uploads are not accepted.",
            field="display_name",
        )
    if suffix != ".csv":
        raise _upload_error(
            ErrorCode.UNSUPPORTED_FILE_TYPE,
            "Only CSV uploads are accepted.",
            field="display_name",
        )
    return display_name


def normalize_csv_upload(
    payload: bytes | bytearray | memoryview | BinaryIO,
    *,
    display_name: str,
    media_type: str | None,
    limits: UploadLimits,
) -> NormalizedCsv:
    """Read, validate, parse, and deterministically normalize a bounded UTF-8 CSV."""

    safe_display_name = validate_display_filename(display_name, limits=limits)
    normalized_media_type = _validate_media_type(media_type)
    raw_bytes = _read_bounded(payload, max_bytes=limits.max_file_size_bytes)
    _reject_known_non_csv_signatures(raw_bytes)
    text = _decode_utf8_csv(raw_bytes)

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        rows: list[list[str]] = []
        expected_columns: int | None = None
        data_row_count = 0
        for row_number, row in enumerate(reader):
            column_count = len(row)
            if column_count > limits.max_columns:
                raise _upload_error(
                    ErrorCode.TOO_MANY_COLUMNS,
                    "The CSV exceeds the configured column limit.",
                    field="upload",
                )
            if row_number == 0:
                if column_count == 0 or all(value == "" for value in row):
                    raise _malformed_csv()
                expected_columns = column_count
            else:
                data_row_count += 1
                if data_row_count > limits.max_data_rows:
                    raise _upload_error(
                        ErrorCode.TOO_MANY_ROWS,
                        "The CSV exceeds the configured data-row limit.",
                        field="upload",
                    )
                if column_count != expected_columns:
                    raise _malformed_csv()
            rows.append(row)
    except csv.Error:
        raise _malformed_csv() from None

    if not rows or expected_columns is None:
        raise _malformed_csv()

    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return NormalizedCsv(
        raw_bytes=raw_bytes,
        normalized_bytes=output.getvalue().encode("utf-8"),
        display_name=safe_display_name,
        media_type=normalized_media_type,
        data_row_count=data_row_count,
        column_count=expected_columns,
    )


def _validate_media_type(media_type: str | None) -> str | None:
    if media_type is None or media_type.strip() == "":
        return None
    normalized = media_type.split(";", 1)[0].strip().lower()
    if normalized not in _ACCEPTED_MEDIA_TYPES:
        raise _upload_error(
            ErrorCode.UNSUPPORTED_FILE_TYPE,
            "The upload content type is not supported.",
            field="media_type",
        )
    return normalized


def _read_bounded(
    payload: bytes | bytearray | memoryview | BinaryIO,
    *,
    max_bytes: int,
) -> bytes:
    if isinstance(payload, (bytes, bytearray, memoryview)):
        data = bytes(payload)
        if len(data) > max_bytes:
            raise _too_large()
        return data

    chunks: list[bytes] = []
    bytes_read = 0
    while bytes_read <= max_bytes:
        chunk = payload.read(min(64 * 1024, max_bytes + 1 - bytes_read))
        if chunk in {b"", None}:
            break
        if not isinstance(chunk, bytes):
            raise _malformed_csv()
        chunks.append(chunk)
        bytes_read += len(chunk)
        if bytes_read > max_bytes:
            raise _too_large()
    return b"".join(chunks)


def _reject_known_non_csv_signatures(data: bytes) -> None:
    archive_prefixes = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"\x1f\x8b",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"BZh",
        b"\xfd7zXZ\x00",
    )
    if data.startswith(archive_prefixes) or len(data) >= 262 and data[257:262] == b"ustar":
        raise _upload_error(
            ErrorCode.ARCHIVE_UPLOAD_REJECTED,
            "Archive content is not accepted.",
            field="upload",
        )

    non_csv_prefixes = (
        b"%PDF-",
        b"#!",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"MZ",
        b"\x7fELF",
        b"SQLite format 3\x00",
        b"\xca\xfe\xba\xbe",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    )
    if data.startswith(non_csv_prefixes):
        raise _upload_error(
            ErrorCode.UNSUPPORTED_FILE_TYPE,
            "The uploaded content is not CSV data.",
            field="upload",
        )


def _decode_utf8_csv(data: bytes) -> str:
    if b"\x00" in data:
        raise _binary_content()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise _binary_content() from None
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        raise _binary_content()
    return text


def _upload_error(
    code: ErrorCode,
    message: str,
    *,
    field: str,
) -> ApplicationError:
    return ApplicationError(code, message, field=field)


def _too_large() -> ApplicationError:
    return _upload_error(
        ErrorCode.UPLOAD_TOO_LARGE,
        "The upload exceeds the configured file-size limit.",
        field="upload",
    )


def _malformed_csv() -> ApplicationError:
    return _upload_error(
        ErrorCode.MALFORMED_CSV,
        "The uploaded CSV is malformed.",
        field="upload",
    )


def _binary_content() -> ApplicationError:
    return _upload_error(
        ErrorCode.BINARY_OR_NUL_CONTENT,
        "Binary or NUL content is not accepted.",
        field="upload",
    )
