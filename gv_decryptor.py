import argparse
import binascii
import mmap
import os
import re
import struct
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from math import lcm

from Crypto.Cipher import DES
from Crypto.Util.strxor import strxor

END_MARKER = b"<<tyfs<<"
INNER_MARKER = b">>tyfs>>"
FIELD_INFO = b"\x01\x01"
VAULT_PATTERN = re.compile(r"\.galleryvault_DoNotDelete_\d+")
CHUNK_SIZE = 1024 * 1024
TAIL_SCAN_SIZE = 1024 * 1024


class DecryptError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RecoveryCancelled(Exception):
    pass


@dataclass(frozen=True)
class ParsedLayout:
    encrypted_xor_key: bytes
    payload_ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class FileResult:
    ok: bool
    status: str
    output_path: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class DiscoveryResult:
    files: list[str]
    vaults: list[str]


def default_output_dir(target: str) -> str:
    target = os.path.abspath(os.path.expanduser(target))
    return target.rstrip(os.sep) + "_recovered"


def output_base_for(input_path: str, target: str, output_dir: str) -> str:
    if os.path.isfile(target):
        relative = os.path.basename(input_path)
    else:
        relative = os.path.relpath(input_path, target)
    return os.path.join(output_dir, relative)


def _is_within(path: str, parent: str | None) -> bool:
    if not parent:
        return False
    try:
        return os.path.commonpath((os.path.realpath(path), parent)) == parent
    except ValueError:
        return False


def _walk_files(root: str, recursive: bool, excluded_dir: str | None) -> list[str]:
    files = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if not os.path.islink(os.path.join(current, directory))
            and not _is_within(os.path.join(current, directory), excluded_dir)
        )
        for name in sorted(names):
            path = os.path.join(current, name)
            if not os.path.islink(path) and not _is_within(path, excluded_dir):
                files.append(path)
        if not recursive:
            break
    return files


def discover_files(
    target: str,
    *,
    smart: bool = True,
    recursive: bool = True,
    output_dir: str | None = None,
) -> DiscoveryResult:
    target = os.path.abspath(os.path.expanduser(target))
    excluded_dir = os.path.realpath(output_dir) if output_dir else None

    if not os.path.exists(target):
        raise FileNotFoundError(f"Input path does not exist: {target}")
    if os.path.isfile(target):
        if os.path.islink(target):
            raise ValueError("Symbolic-link inputs are not supported")
        return DiscoveryResult([target], [])
    if not os.path.isdir(target):
        raise ValueError(f"Input path is not a regular file or directory: {target}")

    if not smart:
        return DiscoveryResult(_walk_files(target, recursive, excluded_dir), [])

    vaults = []
    for current, dirs, _ in os.walk(target, followlinks=False):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if not os.path.islink(os.path.join(current, directory))
            and not _is_within(os.path.join(current, directory), excluded_dir)
        )
        for directory in dirs:
            if VAULT_PATTERN.fullmatch(directory):
                vaults.append(os.path.join(current, directory))
        if not recursive:
            break

    files = []
    for vault in vaults:
        assets_root = os.path.join(vault, "files")
        if os.path.isdir(assets_root):
            files.extend(_walk_files(assets_root, True, excluded_dir))

    return DiscoveryResult(sorted(set(files)), sorted(vaults))


def detect_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return ".wav"
    if data.startswith(b"RIFF") and data[8:12] == b"AVI ":
        return ".avi"
    if data.startswith(b"%PDF-"):
        return ".pdf"
    if data.startswith(b"OggS"):
        return ".ogg"
    if data.startswith(b"\x1aE\xdf\xa3"):
        return ".mkv"
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in {
            b"heic",
            b"heix",
            b"hevc",
            b"hevx",
            b"heif",
            b"heis",
            b"mif1",
            b"msf1",
        }:
            return ".heic"
        if brand in {b"avif", b"avis"}:
            return ".avif"
        if brand in {b"3gp4", b"3gp5", b"3gp6", b"3ge6", b"3gg6"}:
            return ".3gp"
        if brand == b"qt  ":
            return ".mov"
        return ".mp4"
    if data.startswith(b"ID3") or (
        len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0
    ):
        return ".mp3"
    return ".bin"


def _output_with_extension(output_path: str, extension: str) -> str:
    if output_path.lower().endswith(".decrypted"):
        output_path = output_path[: -len(".decrypted")]
    root, current_extension = os.path.splitext(output_path)
    if current_extension.lower() == extension:
        return output_path
    if current_extension:
        return root + extension
    return output_path + extension


class GalleryVaultDecryptor:
    """Decrypt Gallery Vault V2 files."""

    def __init__(self) -> None:
        self._seed = "good_gv"
        self._encrypted_master_key = "5283CBBD2FE1AAF43503D1DDD64DFDD6"
        self._master_key = self._derive_master_key()

    @staticmethod
    def _des_key(value: str) -> bytes:
        padded = (value + ("0" * 16))[:16]
        return padded[:8].encode("utf-8")

    def _derive_master_key(self) -> str:
        cipher = DES.new(self._des_key(self._seed), DES.MODE_ECB)
        encrypted = binascii.unhexlify(self._encrypted_master_key)
        padding = "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
        return cipher.decrypt(encrypted).decode("utf-8", errors="ignore").strip(padding)

    @staticmethod
    def xor_transform(data: bytes, xor_key: bytes, offset: int = 0) -> bytes:
        if not xor_key:
            raise ValueError("XOR key must not be empty")
        if offset < 0:
            raise ValueError("XOR offset must not be negative")
        if not data:
            return b""

        period = min(lcm(256, len(xor_key)), len(data))
        mask_pattern = bytes(
            ((offset + index) & 0xFF) ^ xor_key[(offset + index) % len(xor_key)]
            for index in range(period)
        )
        mask = (mask_pattern * ((len(data) + period - 1) // period))[: len(data)]
        return strxor(data, mask)

    @staticmethod
    def _parse_layout(data: object) -> ParsedLayout:
        end_marker_start = data.rfind(END_MARKER)  # type: ignore[attr-defined]
        if end_marker_start < 0:
            raise DecryptError("NOT_GV", "Gallery Vault end marker was not found")

        end_pos = end_marker_start + len(END_MARKER)
        if end_pos < 59:
            raise DecryptError("CORRUPT_STRUCTURE", "Container tail is truncated")
        if data[end_pos - 10 : end_pos - 8] != FIELD_INFO:  # type: ignore[index]
            raise DecryptError(
                "UNSUPPORTED_VERSION", "Unsupported Gallery Vault version"
            )

        try:
            metadata_len = struct.unpack_from(">Q", data, end_pos - 18)[0]
        except (struct.error, TypeError) as error:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Metadata length is missing"
            ) from error

        xor_len_pos = end_pos - 18 - metadata_len - 8
        if xor_len_pos < 17 or xor_len_pos + 8 > end_pos - 18:
            raise DecryptError("CORRUPT_STRUCTURE", "Metadata length is out of bounds")

        try:
            xor_data_len = struct.unpack_from(">Q", data, xor_len_pos)[0]
        except (struct.error, TypeError) as error:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Encrypted key length is missing"
            ) from error
        if xor_data_len == 0 or xor_data_len > 4096 or xor_data_len % 8:
            raise DecryptError("CORRUPT_STRUCTURE", "Encrypted key length is invalid")

        encrypted_key_pos = xor_len_pos - xor_data_len
        tail_fields_pos = encrypted_key_pos - 17
        if tail_fields_pos < 0:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Container offsets are out of bounds"
            )

        try:
            thumb_len = struct.unpack_from(">Q", data, encrypted_key_pos - 17)[0]
            original_file_len = struct.unpack_from(">Q", data, encrypted_key_pos - 9)[0]
            check_byte = data[encrypted_key_pos - 1]  # type: ignore[index]
        except (IndexError, struct.error, TypeError) as error:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Container fields are truncated"
            ) from error

        if check_byte not in (0, 1):
            raise DecryptError("CORRUPT_STRUCTURE", "Unknown payload layout")
        if thumb_len > original_file_len:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Thumbnail length exceeds payload boundary"
            )
        if original_file_len + len(INNER_MARKER) > tail_fields_pos:
            raise DecryptError(
                "CORRUPT_STRUCTURE", "Payload overlaps container metadata"
            )
        if data[original_file_len : original_file_len + 8] != INNER_MARKER:  # type: ignore[index]
            raise DecryptError("CORRUPT_STRUCTURE", "Inner marker is missing")

        if check_byte == 0:
            payload_ranges = ((thumb_len, original_file_len),)
        else:
            swapped_end = original_file_len + len(INNER_MARKER) + thumb_len
            if swapped_end > tail_fields_pos:
                raise DecryptError(
                    "CORRUPT_STRUCTURE", "Swapped payload block is truncated"
                )
            payload_ranges = (
                (original_file_len + len(INNER_MARKER), swapped_end),
                (thumb_len, original_file_len),
            )

        encrypted_xor_key = bytes(data[encrypted_key_pos:xor_len_pos])  # type: ignore[index]
        return ParsedLayout(encrypted_xor_key, payload_ranges)

    def _xor_key(self, layout: ParsedLayout) -> bytes:
        cipher = DES.new(self._des_key(self._master_key), DES.MODE_ECB)
        return cipher.decrypt(layout.encrypted_xor_key)[:4]

    def decrypt(self, data: bytes) -> bytes:
        layout = self._parse_layout(data)
        encrypted_payload = b"".join(
            data[start:end] for start, end in layout.payload_ranges
        )
        return self.xor_transform(encrypted_payload, self._xor_key(layout))

    def _decrypted_prefix(
        self, data: mmap.mmap, layout: ParsedLayout, xor_key: bytes, size: int = 64
    ) -> bytes:
        parts = []
        output_offset = 0
        remaining = size
        for start, end in layout.payload_ranges:
            if remaining <= 0:
                break
            chunk = bytes(data[start : min(end, start + remaining)])
            parts.append(self.xor_transform(chunk, xor_key, output_offset))
            output_offset += len(chunk)
            remaining -= len(chunk)
        return b"".join(parts)

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        *,
        overwrite: bool = False,
        should_cancel: Callable[[], bool] | None = None,
    ) -> FileResult:
        input_path = os.path.abspath(os.path.expanduser(input_path))
        output_path = os.path.abspath(os.path.expanduser(output_path))
        temporary_path = None

        try:
            file_size = os.path.getsize(input_path)
            if file_size < 59:
                return FileResult(
                    False, "TOO_SMALL", error="File is too small to be a V2 container"
                )

            with open(input_path, "rb") as source:
                source.seek(max(0, file_size - TAIL_SCAN_SIZE))
                if END_MARKER not in source.read():
                    return FileResult(
                        False, "NOT_GV", error="Gallery Vault marker was not found"
                    )

                source.seek(0)
                with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    layout = self._parse_layout(mapped)
                    xor_key = self._xor_key(layout)
                    extension = detect_extension(
                        self._decrypted_prefix(mapped, layout, xor_key)
                    )
                    final_output = _output_with_extension(output_path, extension)

                    if os.path.realpath(input_path) == os.path.realpath(final_output):
                        return FileResult(
                            False,
                            "INVALID_OUTPUT",
                            error="Output path would overwrite the encrypted source",
                        )
                    if os.path.exists(final_output) and not overwrite:
                        return FileResult(
                            False,
                            "EXISTS",
                            output_path=final_output,
                            error="Output file already exists",
                        )

                    parent = os.path.dirname(final_output)
                    os.makedirs(parent, exist_ok=True)
                    descriptor, temporary_path = tempfile.mkstemp(
                        prefix=f".{os.path.basename(final_output)}.",
                        suffix=".part",
                        dir=parent,
                    )

                    with os.fdopen(descriptor, "wb") as recovered:
                        output_offset = 0
                        for start, end in layout.payload_ranges:
                            position = start
                            while position < end:
                                if should_cancel and should_cancel():
                                    raise RecoveryCancelled
                                chunk_end = min(position + CHUNK_SIZE, end)
                                chunk = bytes(mapped[position:chunk_end])
                                recovered.write(
                                    self.xor_transform(chunk, xor_key, output_offset)
                                )
                                output_offset += len(chunk)
                                position = chunk_end
                        recovered.flush()
                        os.fsync(recovered.fileno())

                    if os.path.exists(final_output) and not overwrite:
                        os.unlink(temporary_path)
                        temporary_path = None
                        return FileResult(
                            False,
                            "EXISTS",
                            output_path=final_output,
                            error="Output file was created during recovery",
                        )
                    os.replace(temporary_path, final_output)
                    temporary_path = None
                    return FileResult(True, "RECOVERED", output_path=final_output)
        except RecoveryCancelled:
            return FileResult(False, "CANCELLED", error="Recovery was cancelled")
        except DecryptError as error:
            return FileResult(False, error.code, error=str(error))
        except OSError as error:
            return FileResult(False, "IO_ERROR", error=str(error))
        # Keep a bad candidate from aborting an entire batch recovery.
        except Exception as error:  # noqa: BLE001
            return FileResult(False, "INTERNAL_ERROR", error=str(error))
        finally:
            if temporary_path and os.path.exists(temporary_path):
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover Gallery Vault V2 assets")
    parser.add_argument(
        "input", help="Gallery Vault dump, directory, or encrypted file"
    )
    parser.add_argument("--out", help="Output directory (default: INPUT_recovered)")
    parser.add_argument(
        "--manual",
        "--scan-all",
        dest="scan_all",
        action="store_true",
        help="Scan all files instead of discovering Gallery Vault repositories",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only discover or scan the top level",
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="Replace existing recovered files"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show skipped files and error details"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = os.path.abspath(os.path.expanduser(args.input))
    output_dir = os.path.abspath(
        os.path.expanduser(args.out or default_output_dir(target))
    )

    if os.path.isdir(target) and os.path.realpath(target) == os.path.realpath(
        output_dir
    ):
        print(
            "[ERROR] Output directory must be different from the input directory.",
            file=sys.stderr,
        )
        return 2

    try:
        discovery = discover_files(
            target,
            smart=not args.scan_all,
            recursive=not args.no_recursive,
            output_dir=output_dir,
        )
    except (FileNotFoundError, ValueError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    print(f"[*] Input: {target}")
    print(f"[*] Output: {output_dir}")
    for vault in discovery.vaults:
        print(f"[+] Repository: {vault}")

    if not discovery.files:
        print("[-] No candidate assets found.")
        return 1

    decryptor = GalleryVaultDecryptor()
    counts: Counter[str] = Counter()
    total = len(discovery.files)
    print(f"[*] Processing {total} candidate assets...")

    quiet_statuses = {"NOT_GV", "TOO_SMALL"}
    for index, input_path in enumerate(discovery.files, 1):
        output_base = output_base_for(input_path, target, output_dir)
        result = decryptor.decrypt_file(
            input_path, output_base, overwrite=args.overwrite
        )
        counts[result.status] += 1
        relative = (
            os.path.relpath(input_path, target)
            if os.path.isdir(target)
            else os.path.basename(input_path)
        )
        if result.ok:
            print(f"[{index}/{total}] RECOVERED {relative} -> {result.output_path}")
        elif args.verbose or result.status not in quiet_statuses:
            detail = f": {result.error}" if result.error else ""
            print(f"[{index}/{total}] {result.status} {relative}{detail}")

    recovered = counts["RECOVERED"]
    skipped = counts["NOT_GV"] + counts["TOO_SMALL"]
    failures = total - recovered - skipped
    print(
        f"[DONE] recovered={recovered} skipped={skipped} failed={failures} "
        f"output={output_dir}"
    )
    if args.verbose:
        print(
            "[*] Statuses: "
            + ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
        )
    return 0 if recovered and failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
