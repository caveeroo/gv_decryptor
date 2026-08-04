import struct

import pytest

from gv_decryptor import (
    DecryptError,
    GalleryVaultDecryptor,
    detect_extension,
    discover_files,
    main,
)

PLAINTEXT = b"\x89PNG\r\n\x1a\n" + (b"gallery-vault-test-data" * 20)
XOR_KEY = b"K3y!"
ENCRYPTED_XOR_KEY = bytes.fromhex("5273be321b207813")


def make_fixture(check_byte=0, plaintext=PLAINTEXT):
    decryptor = GalleryVaultDecryptor()
    ciphertext = decryptor.xor_transform(plaintext, XOR_KEY)
    thumbnail = b"thumbnail-placeholder"

    if check_byte == 0:
        body = thumbnail + ciphertext
        original_file_len = len(body)
        swapped_block = b""
    else:
        body = thumbnail + ciphertext[len(thumbnail) :]
        original_file_len = len(body)
        swapped_block = ciphertext[: len(thumbnail)]

    metadata = b"fixture-metadata"
    return b"".join(
        (
            body,
            b">>tyfs>>",
            swapped_block,
            struct.pack(">Q", len(thumbnail)),
            struct.pack(">Q", original_file_len),
            bytes([check_byte]),
            ENCRYPTED_XOR_KEY,
            struct.pack(">Q", len(ENCRYPTED_XOR_KEY)),
            metadata,
            struct.pack(">Q", len(metadata)),
            b"\x01\x01",
            b"<<tyfs<<",
        )
    )


@pytest.mark.parametrize("check_byte", [0, 1])
def test_decrypts_both_payload_layouts(check_byte):
    decryptor = GalleryVaultDecryptor()
    assert decryptor.decrypt(make_fixture(check_byte)) == PLAINTEXT


def test_xor_transform_is_chunk_safe():
    decryptor = GalleryVaultDecryptor()
    data = bytes(range(256)) * 5
    complete = decryptor.xor_transform(data, XOR_KEY)
    split = 333
    chunked = decryptor.xor_transform(data[:split], XOR_KEY)
    chunked += decryptor.xor_transform(data[split:], XOR_KEY, offset=split)
    assert chunked == complete
    assert decryptor.xor_transform(complete, XOR_KEY) == data


def test_recovery_is_atomic_and_does_not_overwrite(tmp_path):
    encrypted = tmp_path / "encrypted_asset"
    encrypted.write_bytes(make_fixture())
    output_base = tmp_path / "recovered"

    first = GalleryVaultDecryptor().decrypt_file(str(encrypted), str(output_base))
    assert first.ok
    assert first.output_path == str(tmp_path / "recovered.png")
    assert (tmp_path / "recovered.png").read_bytes() == PLAINTEXT

    second = GalleryVaultDecryptor().decrypt_file(str(encrypted), str(output_base))
    assert not second.ok
    assert second.status == "EXISTS"
    assert not list(tmp_path.glob("*.part"))


def test_basename_only_output_is_supported(tmp_path, monkeypatch):
    encrypted = tmp_path / "encrypted_asset"
    encrypted.write_bytes(make_fixture())
    monkeypatch.chdir(tmp_path)

    result = GalleryVaultDecryptor().decrypt_file(str(encrypted), "recovered")
    assert result.ok
    assert (tmp_path / "recovered.png").read_bytes() == PLAINTEXT


def test_cancel_removes_partial_output(tmp_path):
    encrypted = tmp_path / "encrypted_asset"
    encrypted.write_bytes(make_fixture(plaintext=b"x" * (1024 * 1024 + 10)))

    checks = 0

    def cancel_after_one_chunk():
        nonlocal checks
        checks += 1
        return checks > 1

    result = GalleryVaultDecryptor().decrypt_file(
        str(encrypted),
        str(tmp_path / "cancelled"),
        should_cancel=cancel_after_one_chunk,
    )
    assert result.status == "CANCELLED"
    assert not (tmp_path / "cancelled.bin").exists()
    assert not list(tmp_path.glob("*.part"))


def test_rejects_bad_version_and_truncated_input():
    decryptor = GalleryVaultDecryptor()
    wrong_version = bytearray(make_fixture())
    wrong_version[-10:-8] = b"\x02\x00"
    with pytest.raises(DecryptError, match="Unsupported"):
        decryptor.decrypt(bytes(wrong_version))
    with pytest.raises(DecryptError, match="end marker"):
        decryptor.decrypt(b"not a Gallery Vault file")

    bad_metadata_length = bytearray(make_fixture())
    bad_metadata_length[-18:-10] = struct.pack(">Q", 10_000_000)
    with pytest.raises(DecryptError, match="out of bounds"):
        decryptor.decrypt(bytes(bad_metadata_length))


@pytest.mark.parametrize(
    ("header", "extension"),
    [
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"RIFF\x00\x00\x00\x00WEBP", ".webp"),
        (b"\x00\x00\x00\x18ftypheic", ".heic"),
        (b"%PDF-1.7", ".pdf"),
        (b"OggS", ".ogg"),
        (b"unknown", ".bin"),
    ],
)
def test_detect_extension(header, extension):
    assert detect_extension(header) == extension


def test_discovery_is_shared_exact_and_excludes_output(tmp_path):
    vault_files = tmp_path / ".galleryvault_DoNotDelete_42" / "files"
    vault_files.mkdir(parents=True)
    asset = vault_files / "a"
    asset.write_bytes(make_fixture())

    fake_files = tmp_path / ".galleryvault_DoNotDelete_42_extra" / "files"
    fake_files.mkdir(parents=True)
    (fake_files / "ignored").write_bytes(make_fixture())

    output = tmp_path / "recovered"
    output.mkdir()
    (output / "old.png").write_bytes(b"old")

    smart = discover_files(str(tmp_path), smart=True, output_dir=str(output))
    assert smart.files == [str(asset)]
    assert smart.vaults == [str(vault_files.parent)]

    manual = discover_files(str(tmp_path), smart=False, output_dir=str(output))
    assert str(output / "old.png") not in manual.files
    assert str(asset) in manual.files


def test_discovery_accepts_a_single_file(tmp_path):
    source = tmp_path / "asset"
    source.write_bytes(make_fixture())
    result = discover_files(str(source), smart=True)
    assert result.files == [str(source)]


def test_cli_rejects_missing_input(capsys):
    exit_code = main(["/definitely/not/a/gallery-vault-path"])
    assert exit_code == 2
    assert "does not exist" in capsys.readouterr().err
