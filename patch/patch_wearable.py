#!/usr/bin/env python3
"""
Патчит смали Samsung Wearable.
"""

import os
import re
import sys


# ---------- helpers ----------

def get_registers(method: str) -> int:
    m = re.search(r'\.registers\s+(\d+)', method)
    if m:
        return max(int(m.group(1)), 1)
    m = re.search(r'\.locals\s+(\d+)', method)
    if m:
        sig = re.search(r'\(([^)]*)\)', method.split('\n')[0])
        params = 0
        if sig:
            s, i = sig.group(1), 0
            while i < len(s):
                if s[i] == 'L':
                    i = s.index(';', i) + 1
                elif s[i] == '[': i += 1; continue
                else:
                    params += 2 if s[i] in 'JD' else 1
                    i += 1
        is_static = 'static' in method.split('\n')[0]
        return max(int(m.group(1)) + params + (0 if is_static else 1), 1)
    return 2


def to_true(method: str) -> str:
    first = method.split('\n')[0]
    return f"{first}\n    .registers {get_registers(method)}\n    const/4 v0, 0x1\n    return v0\n.end method"


def to_false(method: str) -> str:
    first = method.split('\n')[0]
    return f"{first}\n    .registers {get_registers(method)}\n    const/4 v0, 0x0\n    return v0\n.end method"


def to_zero_int(method: str) -> str:
    first = method.split('\n')[0]
    return f"{first}\n    .registers {get_registers(method)}\n    const/4 v0, 0x0\n    return v0\n.end method"


def find_methods(content: str, return_type: str):
    pat = re.compile(
        r'(\.method\s+[^\n]*\)' + re.escape(return_type) + r'\n'
        r'(?:(?!\.end method)[\s\S])*?\.end method)',
        re.MULTILINE)
    return list(pat.finditer(content))


# ---------- patch file ----------

def patch_file(filepath: str, stats: dict) -> int:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        original = f.read()

    out = original
    count = 0

    # S1: boolean methods reading Build.MANUFACTURER + comparing "samsung"
    for m in find_methods(original, 'Z'):
        body = m.group(0)
        if ('Landroid/os/Build;->MANUFACTURER' in body
                and 'samsung' in body.lower()):
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1); count += 1
                print(f'  [S1-MANUFACTURER] {os.path.basename(filepath)} :: {body.split(chr(10))[0].strip()}')
                stats['s1'] += 1

    # S2: known method name patterns
    BOOL_NAMES = ['isSamsungDevice','isSamsungPhone','isSupportedPhone','isCompatiblePhone',
                  'isSupportedDevice','checkCompatibility','isPhoneSupported','isAllowedDevice',
                  'isSupportedModel','isTargetDevice','checkDeviceSupport']
    for name in BOOL_NAMES:
        for m in re.finditer(
            r'(\.method\s+[^\n]*' + re.escape(name) + r'[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)',
            out, re.MULTILINE):
            body = m.group(0)
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1); count += 1
                print(f'  [S2-name:{name}] {os.path.basename(filepath)}')
                stats['s2'] += 1

    # S3: Knox isDeviceRooted -> false, getWarrantyBit -> 0
    for m in re.finditer(
        r'(\.method\s+[^\n]*isDeviceRooted[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)',
        out, re.MULTILINE):
        body = m.group(0)
        repl = to_false(body)
        if body != repl:
            out = out.replace(body, repl, 1); count += 1
            print(f'  [S3-Knox-rooted] {os.path.basename(filepath)}')
            stats['s3'] += 1

    for m in re.finditer(
        r'(\.method\s+[^\n]*getWarrantyBit[^\n]*\)I\n(?:(?!\.end method)[\s\S])*?\.end method)',
        out, re.MULTILINE):
        body = m.group(0)
        repl = to_zero_int(body)
        if body != repl:
            out = out.replace(body, repl, 1); count += 1
            print(f'  [S3-Knox-warranty] {os.path.basename(filepath)}')
            stats['s3'] += 1

    # S4: boolean methods that call ANY Knox class -> return true
    for m in find_methods(out, 'Z'):
        body = m.group(0)
        if 'Lcom/samsung/android/knox/' in body:
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1); count += 1
                print(f'  [S4-KnoxCaller] {os.path.basename(filepath)} :: {body.split(chr(10))[0].strip()}')
                stats['s4'] += 1

    # S5: boolean methods that read PackageInfo.signatures (self-sign check)
    for m in find_methods(out, 'Z'):
        body = m.group(0)
        if ('PackageInfo;->signatures' in body
                or 'PackageInfo;->signingInfo' in body
                or 'GET_SIGNATURES' in body
                or ('getPackageInfo' in body and '0x40' in body)):
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1); count += 1
                print(f'  [S5-Signature] {os.path.basename(filepath)} :: {body.split(chr(10))[0].strip()}')
                stats['s5'] += 1

    # S6: boolean methods that call Build.FINGERPRINT or Build.TAGS
    for m in find_methods(out, 'Z'):
        body = m.group(0)
        if ('Landroid/os/Build;->FINGERPRINT' in body
                or 'Landroid/os/Build;->TAGS' in body
                or 'Landroid/os/Build;->TYPE' in body):
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1); count += 1
                print(f'  [S6-BuildField] {os.path.basename(filepath)} :: {body.split(chr(10))[0].strip()}')
                stats['s6'] += 1

    if out != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(out)
    return count


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: patch_wearable.py <smali_root>')
        sys.exit(1)

    base = sys.argv[1]
    stats = {'s1': 0, 's2': 0, 's3': 0, 's4': 0, 's5': 0, 's6': 0}
    total_files = 0
    total_patches = 0

    subdirs = [d for d in ['smali','smali_classes2','smali_classes3',
                            'smali_classes4','smali_classes5']
               if os.path.isdir(os.path.join(base, d))]

    print(f'Smali dirs found: {subdirs}')

    for sub in subdirs:
        path = os.path.join(base, sub)
        for dirpath, _, files in os.walk(path):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dirpath, fn), stats)

    print(f'\n=== Summary ===')
    print(f'Files scanned : {total_files}')
    print(f'Total patches : {total_patches}')
    print(f'  S1 Build.MANUFACTURER : {stats["s1"]}')
    print(f'  S2 method names       : {stats["s2"]}')
    print(f'  S3 Knox direct        : {stats["s3"]}')
    print(f'  S4 Knox callers       : {stats["s4"]}')
    print(f'  S5 signature check    : {stats["s5"]}')
    print(f'  S6 Build fields       : {stats["s6"]}')

    if total_patches == 0:
        print('WARNING: nothing patched — check may be in native .so library')
        sys.exit(2)
