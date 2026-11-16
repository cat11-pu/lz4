#!/usr/bin/env python3

import hashlib
import os
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "artifacts" / "samples"

EXPECTED = {
    "texture.gpk": [
        "b355d29b307127fad8258ab0cd7cada2e32ea8d7f40bf0d968e57c0c74f6479f",
        "c867cc1aafca436ffbde5ae289711637bcd8629d65aee31e51024c51b38c8853",
    ],
    "mesh.gpk": [
        "5177d4389017e3b467edc51e9652cf1c7260b71d462233efe1166582708e06af",
        "75acc5fab08cd896e3395d8f699cec620864a6b55850948da1429eb40e6aaaf0",
    ],
    "audio.gpk": [
        "c74edd08303675e2589a03efd58dae86199b708bfdc5e5c1ab710d8e15043c6b",
        "773f707b60c08a1bee4d53b5dac38dd7a48c9a4a1c1a6aec7436fa3a3f880e90",
    ],
}


def le32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def chunks(data):
    count = struct.unpack_from("<I", data, 8)[0]
    pos = 12
    result = []
    for index in range(count):
        if pos + 16 > len(data):
            break
        chunk_type, flags, csize, usize = struct.unpack_from("<IIII", data, pos)
        result.append({
            "index": index,
            "record": pos,
            "payload": pos + 16,
            "type": chunk_type,
            "flags": flags,
            "csize": csize,
            "usize": usize,
        })
        pos += 16 + csize
    return result


def mutate(data, pos, value):
    result = bytearray(data)
    result[pos:pos + len(value)] = value
    return bytes(result)


def malformed_cases(name, data):
    cases = []

    def add(label, blob):
        cases.append(("%s:%s" % (name, label), blob))

    add("empty", b"")
    add("magic-only", b"GPK1")
    add("short-global-header", data[:11])
    add("bad-magic", mutate(data, 0, b"GPK2"))
    add("bad-version", mutate(data, 4, le32(2)))
    add("zero-chunks", mutate(data, 8, le32(0)))
    add("huge-chunks", mutate(data, 8, le32(0xFFFFFFFF)))
    add("chunks-do-not-fit", mutate(data, 8, le32(len(data) // 16 + 1)))
    add("trailing-byte", data + b"\x00")

    cuts = set(range(0, 13))
    parsed = chunks(data)
    for chunk in parsed:
        for base in (chunk["record"], chunk["payload"],
                     chunk["payload"] + chunk["csize"]):
            for delta in range(-1, 21):
                cut = base + delta
                if 0 <= cut < len(data):
                    cuts.add(cut)
    for delta in range(1, 17):
        cuts.add(len(data) - delta)
    for cut in sorted(cuts):
        add("truncate-%d" % cut, data[:cut])

    for chunk in parsed:
        record = chunk["record"]
        payload = chunk["payload"]
        csize = chunk["csize"]

        for value in (0, 4, 0xFFFFFFFF):
            add("chunk-%d-type-%x" % (chunk["index"], value),
                mutate(data, record, le32(value)))
        for value in (1, 0x80000000, 0xFFFFFFFF):
            add("chunk-%d-flags-%x" % (chunk["index"], value),
                mutate(data, record + 4, le32(value)))
        for value in (0, 1, csize - 1 if csize else 0, csize + 1,
                      len(data) - payload, len(data) - payload + 1,
                      0xFFFFFFFF):
            if value >= 0 and value != csize:
                add("chunk-%d-csize-%x" % (chunk["index"], value),
                    mutate(data, record + 8, le32(value)))
        for value in (0, 1, chunk["usize"] - 1 if chunk["usize"] else 0,
                      chunk["usize"] + 1, 0xFFFFFFFF):
            if value >= 0:
                add("chunk-%d-usize-%x" % (chunk["index"], value),
                    mutate(data, record + 12, le32(value)))

        if csize >= 7:
            add("chunk-%d-frame-magic" % chunk["index"],
                mutate(data, payload, b"\x00\x00\x00\x00"))
            flg = data[payload + 4]
            for value in (0x00, 0x40, 0x80, 0xC0, 0xFF,
                          flg ^ 0x02, flg ^ 0x20, flg ^ 0x40):
                add("chunk-%d-flg-%02x" % (chunk["index"], value),
                    mutate(data, payload + 4, bytes([value])))
            bd = data[payload + 5]
            for value in (0x00, 0x30, 0x80, 0x8F, 0xF0, bd ^ 0x01, bd ^ 0x10):
                add("chunk-%d-bd-%02x" % (chunk["index"], value),
                    mutate(data, payload + 5, bytes([value])))
            add("chunk-%d-hc" % chunk["index"],
                mutate(data, payload + 6, bytes([data[payload + 6] ^ 0x80])))

            header_size = 7
            if flg & 0x08:
                header_size += 8
            if flg & 0x01:
                header_size += 4
            if csize >= header_size + 4:
                block = payload + header_size
                original = struct.unpack_from("<I", data, block)[0]
                for value in (0, 1, 0x7FFFFFFF, 0x80000000, 0x80000001,
                              original ^ 1, original + 1):
                    add("chunk-%d-block-%08x" % (chunk["index"], value),
                        mutate(data, block, le32(value)))

        for pos in range(payload, min(payload + 32, payload + csize)):
            add("chunk-%d-byte-%d-01" % (chunk["index"], pos - payload),
                mutate(data, pos, bytes([data[pos] ^ 0x01])))
            add("chunk-%d-byte-%d-80" % (chunk["index"], pos - payload),
                mutate(data, pos, bytes([data[pos] ^ 0x80])))

    rng = random.Random(0x47504B31)
    for index in range(600):
        blob = bytearray(data)
        mode = index % 3
        if mode == 0:
            blob = blob[:rng.randrange(len(blob))]
        elif mode == 1:
            for _ in range(rng.randrange(1, 9)):
                pos = rng.randrange(12, len(blob))
                blob[pos] ^= 1 << rng.randrange(8)
        else:
            pos = rng.randrange(12, max(13, len(blob) - 4))
            blob[pos:pos + 4] = le32(rng.getrandbits(32))
        add("random-%d" % index, bytes(blob))

    unique = {}
    for label, blob in cases:
        unique.setdefault(blob, label)
    return [(label, blob) for blob, label in unique.items()]


def check_valid(loader, env):
    failures = 0
    used = 0
    with tempfile.TemporaryDirectory(prefix="gpk-valid.") as tmp:
        for name, hashes in EXPECTED.items():
            path = SAMPLES / name
            if not path.exists():
                print("SKIP valid %s (sample not found)" % name)
                continue
            sample_dir = Path(tmp) / name
            sample_dir.mkdir()
            result = subprocess.run(
                [loader, "extract", str(path), str(sample_dir)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                text=True,
            )
            used += 1
            if result.returncode != 0 or not result.stdout.startswith("ok "):
                print("FAIL valid %s: rc=%d %s" % (name, result.returncode,
                                                   result.stderr.strip()))
                failures += 1
                continue
            for index, expected in enumerate(hashes):
                matches = list(sample_dir.glob("%04d-*.bin" % index))
                if len(matches) != 1:
                    print("FAIL valid %s chunk %d: extracted file missing" %
                          (name, index))
                    failures += 1
                    continue
                digest = hashlib.sha256(matches[0].read_bytes()).hexdigest()
                if digest != expected:
                    print("FAIL valid %s chunk %d: %s != %s" %
                          (name, index, digest, expected))
                    failures += 1
    return used, failures


def check_malformed(loader, env):
    total = 0
    rejected = 0
    accepted = 0
    crashes = 0
    sanitizer = 0
    missing_diagnostic = 0
    sample_names = sorted(EXPECTED)

    with tempfile.TemporaryDirectory(prefix="gpk-malformed.") as tmp:
        case_path = Path(tmp) / "case.gpk"
        for name in sample_names:
            path = SAMPLES / name
            if not path.exists():
                print("SKIP malformed %s (sample not found)" % name)
                continue
            data = path.read_bytes()
            for label, blob in malformed_cases(name, data):
                total += 1
                case_path.write_bytes(blob)
                result = subprocess.run(
                    [loader, "check", str(case_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                    text=True,
                )
                stderr = result.stderr
                if ("AddressSanitizer" in stderr
                        or "runtime error:" in stderr
                        or "UndefinedBehaviorSanitizer" in stderr):
                    sanitizer += 1
                    crashes += 1
                    print("CRASH %s: %s" % (label, stderr.splitlines()[:4]))
                elif result.returncode < 0 or result.returncode >= 128:
                    crashes += 1
                    print("CRASH %s: rc=%d" % (label, result.returncode))
                elif result.returncode == 0:
                    accepted += 1
                    print("ACCEPTED %s" % label)
                else:
                    rejected += 1
                    if ("error=" not in stderr or "chunk=" not in stderr
                            or "offset=" not in stderr):
                        missing_diagnostic += 1
                        print("FAIL diagnostic %s: %s" %
                              (label, stderr.strip()))
    return {
        "cases": total,
        "rejected": rejected,
        "accepted": accepted,
        "crashes": crashes,
        "sanitizer": sanitizer,
        "missing_diagnostic": missing_diagnostic,
    }


def main():
    if len(sys.argv) != 2:
        print("usage: %s GPK_LOADER" % sys.argv[0])
        return 2
    loader = str(Path(sys.argv[1]).resolve())
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=1:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

    valid, valid_failures = check_valid(loader, env)
    stats = check_malformed(loader, env)
    print("valid archives: %d, failures: %d" % (valid, valid_failures))
    print("malformed cases: %(cases)d, rejected: %(rejected)d, "
          "accepted: %(accepted)d, crashes: %(crashes)d, "
          "sanitizer reports: %(sanitizer)d, "
          "missing diagnostics: %(missing_diagnostic)d" % stats)
    return 1 if (valid_failures or stats["accepted"] or stats["crashes"]
                 or stats["missing_diagnostic"]) else 0


if __name__ == "__main__":
    sys.exit(main())
