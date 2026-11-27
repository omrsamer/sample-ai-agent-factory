"""Verify immutable local source independently before resolving Registry context."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024


def validate_archive(raw: dict) -> dict:
    if set(raw) != {"bucketName", "objectKey", "versionId", "sha256", "ownerAccountId"}:
        raise ValueError("sourceArchive has unexpected or missing fields")
    if not all(isinstance(v, str) and v and v == v.strip() for v in raw.values()):
        raise ValueError("sourceArchive fields must be nonempty strings")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", raw["bucketName"]):
        raise ValueError("sourceArchive bucket is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]):
        raise ValueError("sourceArchive checksum is invalid")
    if raw["objectKey"] != f"sources/{raw['sha256']}.zip":
        raise ValueError("sourceArchive key must identify its exact checksum")
    if raw["versionId"] == "null" or len(raw["versionId"]) > 1024:
        raise ValueError("sourceArchive requires an immutable object version")
    if not re.fullmatch(r"\d{12}", raw["ownerAccountId"]):
        raise ValueError("sourceArchive owner must be an account ID")
    return dict(raw)


def verify_archive(s3, raw: dict, checkout: Path) -> dict:
    """Check exact object/version/digest and every extracted source entry.

    CDK build-generated files are permitted, but the original source entries may
    not be changed, omitted, linked outside the checkout, or duplicated.
    """
    archive = validate_archive(raw)
    response = s3.get_object(
        Bucket=archive["bucketName"], Key=archive["objectKey"],
        VersionId=archive["versionId"], ExpectedBucketOwner=archive["ownerAccountId"],
    )
    if response.get("VersionId") != archive["versionId"]:
        raise ValueError("sourceArchive returned a different version")
    if response.get("ContentLength", MAX_ARCHIVE_BYTES + 1) > MAX_ARCHIVE_BYTES:
        raise ValueError("sourceArchive exceeds the size limit")
    try:
        data = response["Body"].read(MAX_ARCHIVE_BYTES + 1)
    finally:
        response["Body"].close()
    if len(data) > MAX_ARCHIVE_BYTES or hashlib.sha256(data).hexdigest() != archive["sha256"]:
        raise ValueError("sourceArchive checksum mismatch")
    checkout = checkout.resolve(strict=True)
    with zipfile.ZipFile(io.BytesIO(data)) as frozen:
        entries = frozen.infolist()
        if not entries or len(entries) > 10000 or sum(e.file_size for e in entries) > MAX_SOURCE_BYTES:
            raise ValueError("sourceArchive expanded size or entry count is invalid")
        seen = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in entry.filename or entry.filename in seen:
                raise ValueError("sourceArchive contains unsafe or duplicate entries")
            seen.add(entry.filename)
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("sourceArchive contains a symbolic link")
            destination = (checkout / entry.filename).resolve(strict=True)
            if not destination.is_relative_to(checkout):
                raise ValueError("sourceArchive entry leaves the checkout")
            if entry.is_dir():
                if not destination.is_dir():
                    raise ValueError("sourceArchive directory is missing")
            elif not destination.is_file() or destination.read_bytes() != frozen.read(entry):
                raise ValueError("extracted source differs from the frozen archive")
    return archive
