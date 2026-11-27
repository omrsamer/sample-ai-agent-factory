"""Immutable local-source verification: corruption, substitution and traversal."""
import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from source_provenance import validate_archive, verify_archive
from test_resolve_ga_registry_context import FakeAws, config, resolver


def fixture(tmp_path, entries=None):
    entries = entries or {"enterprise-agentic-ai-platform-blueprint/package.json": b'{"name":"test"}'}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
            if ".." not in Path(name).parts and not Path(name).is_absolute():
                target = tmp_path / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    data = buffer.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    provenance = {
        "bucketName": "reviewed-source-bucket",
        "objectKey": f"sources/{digest}.zip",
        "versionId": "immutable-version",
        "sha256": digest,
        "ownerAccountId": "222222222222",
    }
    class S3:
        def get_object(self, **kwargs):
            assert kwargs == {
                "Bucket": provenance["bucketName"], "Key": provenance["objectKey"],
                "VersionId": provenance["versionId"], "ExpectedBucketOwner": provenance["ownerAccountId"],
            }
            return {"VersionId": provenance["versionId"], "ContentLength": len(data), "Body": io.BytesIO(data)}
    return S3(), provenance


def test_exact_archive_and_extracted_source(tmp_path):
    s3, archive = fixture(tmp_path)
    assert verify_archive(s3, archive, tmp_path) == archive
    cfg = config(tmp_path, source_archive=archive, source_revision=f"s3-sha256:{archive['sha256']}")
    result = resolver.resolve_context(FakeAws(cfg), cfg)
    assert result["schemaVersion"] == resolver.ARCHIVE_SCHEMA_VERSION
    assert result["sourceArchive"] == archive
    assert result["sourceRevision"].startswith("s3-sha256:")


@pytest.mark.parametrize("field,value", [
    ("versionId", "null"), ("versionId", ""), ("sha256", "a" * 40),
    ("objectKey", "sources/mutable.zip"), ("ownerAccountId", "*"),
    ("bucketName", "bad/bucket"),
])
def test_invalid_provenance(tmp_path, field, value):
    _, archive = fixture(tmp_path)
    archive[field] = value
    with pytest.raises(ValueError):
        validate_archive(archive)


def test_rejects_changed_extracted_source(tmp_path):
    s3, archive = fixture(tmp_path)
    (tmp_path / "enterprise-agentic-ai-platform-blueprint/package.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="differs"):
        verify_archive(s3, archive, tmp_path)


def test_rejects_checksum_substitution(tmp_path):
    s3, archive = fixture(tmp_path)
    original = s3.get_object
    def corrupt(**kwargs):
        response = original(**kwargs)
        response["Body"] = io.BytesIO(b"corruption")
        return response
    s3.get_object = corrupt
    with pytest.raises(ValueError, match="checksum"):
        verify_archive(s3, archive, tmp_path)


def test_rejects_traversal(tmp_path):
    s3, archive = fixture(tmp_path, {"../outside": b"unsafe"})
    with pytest.raises(ValueError, match="unsafe"):
        verify_archive(s3, archive, tmp_path)


def test_rejects_linked_checkout_entry(tmp_path):
    s3, archive = fixture(tmp_path)
    source = tmp_path / "enterprise-agentic-ai-platform-blueprint/package.json"
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(outside)
    with pytest.raises(ValueError, match="leaves"):
        verify_archive(s3, archive, tmp_path)
