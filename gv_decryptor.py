import os
import struct
import binascii
import argparse
import re
from Crypto.Cipher import DES

class GalleryVaultDecryptor:
    """
    A general-purpose decryptor for Gallery Vault (ThinkYeah) encrypted files.
    Handles the V2 file structure, tail parsing, and multi-layer DES key derivation.
    """
    def __init__(self, logger=None):
        self.string_a = "good_gv"
        self.hex_b = "5283CBBD2FE1AAF43503D1DDD64DFDD6"
        self.master_key_str = self._derive_master_key()
        self.logger = logger
        self.blacklist = (".apk", ".so", ".vdex", ".odex", ".art", ".dex", ".xml", ".dm", ".prop", ".version")

    def _log(self, msg):
        if self.logger: self.logger(msg)

    def _pad_key(self, s):
        return s + ("0" * (16 - len(s))) if len(s) < 16 else s[:16]

    def _get_des_key(self, s):
        return self._pad_key(s)[:8].encode('utf-8')

    def _derive_master_key(self):
        key = self._get_des_key(self.string_a)
        cipher = DES.new(key, DES.MODE_ECB)
        data = binascii.unhexlify(self.hex_b)
        return cipher.decrypt(data).decode('utf-8', errors='ignore').strip('\x00\x01\x02\x03\x04\x05\x06\x07\x08')

    def xor_transform(self, data, xor_key, offset=0):
        result = bytearray()
        key_len = len(xor_key)
        for i, b in enumerate(data):
            pos = i + offset
            key_byte = xor_key[pos % key_len]
            pos_byte = pos & 0xFF
            result.append(b ^ pos_byte ^ key_byte)
        return bytes(result)

    def decrypt(self, data, manual_key=None):
        if b"<<tyfs<<" not in data:
            raise ValueError("MISSING_MARKER")

        end_pos = data.rfind(b"<<tyfs<<") + 8
        data = data[:end_pos]
        file_size = len(data)
        
        field_info = data[file_size-10 : file_size-8]
        if field_info != b"\x01\x01":
            raise ValueError(f"UNSUPPORTED_VERSION")

        metadata_len = struct.unpack(">Q", data[file_size-18 : file_size-10])[0]
        xor_len_pos = file_size - 18 - metadata_len - 8
        xor_data_len = struct.unpack(">Q", data[xor_len_pos : xor_len_pos+8])[0]
        enc_xor_pos = xor_len_pos - xor_data_len
        encrypted_xor_key = data[enc_xor_pos : enc_xor_pos + xor_data_len]
        
        check_byte = data[enc_xor_pos - 1]
        orig_file_len = struct.unpack(">Q", data[enc_xor_pos - 9 : enc_xor_pos - 1])[0]
        thumb_len = struct.unpack(">Q", data[enc_xor_pos - 17 : enc_xor_pos - 9])[0]

        if data[orig_file_len : orig_file_len+8] != b">>tyfs>>":
            raise ValueError("CORRUPT_STRUCTURE")

        key = self._get_des_key(self.master_key_str)
        cipher = DES.new(key, DES.MODE_ECB)
        xor_key_full = cipher.decrypt(encrypted_xor_key)
        xor_key = manual_key if manual_key else xor_key_full[:4]
        
        if check_byte == 0:
            encrypted_part = data[thumb_len : orig_file_len]
        else:
            part1 = data[orig_file_len + 8 : orig_file_len + 8 + thumb_len]
            part2 = data[thumb_len : orig_file_len]
            encrypted_part = part1 + part2
        
        return self.xor_transform(encrypted_part, xor_key)

    def decrypt_file(self, input_path, output_path, manual_key=None):
        try:
            if input_path.lower().endswith(self.blacklist):
                return False, "SKIPPED"

            file_size = os.path.getsize(input_path)
            if file_size < 128: return False, "TOO_SMALL"

            with open(input_path, "rb") as f:
                f.seek(max(0, file_size - 4096))
                tail_sample = f.read()
                if b"<<tyfs<<" not in tail_sample:
                    return False, "NOT_GV"
                
                f.seek(0)
                data = f.read()
            
            result = self.decrypt(data, manual_key)
            
            ext = ".bin"
            if result.startswith(b"\x89PNG\r\n\x1a\n"): ext = ".png"
            elif result.startswith(b"\xff\xd8\xff"): ext = ".jpg"
            elif result.startswith(b"GIF8"): ext = ".gif"
            elif b"ftyp" in result[4:12]: ext = ".mp4"
            elif result.startswith(b"ID3") or result.startswith(b"\xff\xfb"): ext = ".mp3"
            elif result.startswith(b"PK\x03\x04"): ext = ".zip"

            final_out = output_path.replace(".decrypted", "")
            if not final_out.endswith(ext): final_out += ext
            
            os.makedirs(os.path.dirname(final_out), exist_ok=True)
            with open(final_out, "wb") as f: f.write(result)
            return True, None
        except Exception as e:
            return False, str(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gallery Vault Decryptor CLI v4.6")
    parser.add_argument("input", help="Target root path")
    parser.add_argument("--out", help="Output directory")
    parser.add_argument("--manual", action="store_true", help="Disable smart repository discovery")

    args = parser.parse_args()
    gv = GalleryVaultDecryptor()
    
    target_root = args.input
    out_dir = args.out or (target_root.rstrip("/") + "_recovered")
    vault_pattern = re.compile(r"\.galleryvault_DoNotDelete_\d+")
    
    print(f"[*] Starting scan on: {target_root}")
    
    assets_to_process = []
    
    if not args.manual:
        print("[*] Running repository discovery...")
        for root, dirs, _ in os.walk(target_root):
            for d in dirs:
                if vault_pattern.match(d):
                    vault_path = os.path.join(root, d)
                    print(f"[+] Repository found: {d}")
                    assets_root = os.path.join(vault_path, "files")
                    if os.path.exists(assets_root):
                        for r, _, fns in os.walk(assets_root):
                            for f in fns:
                                if len(f) > 30:
                                    assets_to_process.append(os.path.join(r, f))
    else:
        for root, _, fns in os.walk(target_root):
            for f in fns: assets_to_process.append(os.path.join(root, f))

    total = len(assets_to_process)
    if total == 0:
        print("[-] No Gallery Vault assets identified.")
    else:
        print(f"[*] Processing {total} assets...")
        success = 0
        for f_path in assets_to_process:
            rel = os.path.relpath(f_path, target_root)
            f_out = os.path.join(out_dir, rel)
            ok, err = gv.decrypt_file(f_path, f_out)
            if ok:
                print(f"  [RECOVERED] {os.path.basename(f_path)}")
                success += 1
        print(f"\n[DONE] Successfully recovered {success}/{total} assets to {out_dir}")