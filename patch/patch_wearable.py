#!/usr/bin/env python3
"""
Патчит смали Samsung Wearable, убирая проверки совместимости устройства.
Стратегии:
  1. Методы, читающие Build.MANUFACTURER и сравнивающие с "samsung" -> return true
  2. Методы с именами isSamsungDevice / isSupportedPhone / ... -> return true
  3. Knox-методы isDeviceRooted / getWarrantyBit -> return false / 0
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
        # count params
        sig = re.search(r'\(([^)]*)\)', method.split('\n')[0])
        params = 0
        if sig:
            s = sig.group(1)
            i = 0
            while i < len(s):
                if s[i] == 'L':
                    i = s.index(';', i) + 1
                elif s[i] == '[':
                    i += 1
                    continue
                else:
                    params += 2 if s[i] in 'JD' else 1
                    i += 1
        is_static = 'static' in method.split('\n')[0]
        return max(int(m.group(1)) + params + (0 if is_static else 1), 1)
    return 2


def to_true(method: str) -> str:
    first = method.split('\n')[0]
    r = get_registers(method)
    return f"{first}\n    .registers {r}\n    const/4 v0, 0x1\n    return v0\n.end method"


def to_zero(method: str) -> str:
    first = method.split('\n')[0]
    r = get_registers(method)
    return f"{first}\n    .registers {r}\n    const/4 v0, 0x0\n    return v0\n.end method"


def method_blocks(content: str, return_type: str):
    """Yield (match_obj) for all method blocks returning given type."""
    pat = re.compile(
        r'(\.method\s+[^\n]*\)' + re.escape(return_type) + r'\n'
        r'(?:(?!\.end method)[\s\S])*?'
        r'\.end method)',
        re.MULTILINE
    )
    return pat.finditer(content)


# ---------- patch strategies ----------

def patch_file(filepath: str) -> int:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        original = f.read()

    out = original
    count = 0

    # --- Strategy 1: boolean methods that read Build.MANUFACTURER + compare samsung ---
    for m in method_blocks(original, 'Z'):
        body = m.group(0)
        if ('Landroid/os/Build;->MANUFACTURER' in body
                and 'samsung' in body.lower()
                and body != to_true(body)):
            out = out.replace(body, to_true(body), 1)
            print(f"  [S1] {filepath}  ->  {body.split(chr(10))[0].strip()}")
            count += 1

    # --- Strategy 2: boolean methods with known compatibility-check names ---
    BOOL_NAMES = [
        'isSamsungDevice', 'isSamsungPhone', 'isSupportedPhone',
        'isCompatiblePhone', 'isSupportedDevice', 'checkCompatibility',
        'isPhoneSupported', 'isTargetDevice', 'checkDeviceSupport',
        'isSupportedModel', 'isAllowedDevice',
    ]
    for name in BOOL_NAMES:
        for m in re.finditer(
            r'(\.method\s+[^\n]*' + re.escape(name) + r'[^\n]*\)Z\n'
            r'(?:(?!\.end method)[\s\S])*?\.end method)',
            out, re.MULTILINE
        ):
            body = m.group(0)
            repl = to_true(body)
            if body != repl:
                out = out.replace(body, repl, 1)
                print(f"  [S2] {filepath}  ->  {name}")
                count += 1

    # --- Strategy 3: Knox methods ---
    for m in re.finditer(
        r'(\.method\s+[^\n]*isDeviceRooted[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)',
        out, re.MULTILINE
    ):
        body = m.group(0)
        repl = to_true(body)  # rooted -> false = return 0 for boolean
        # isDeviceRooted returning false means NOT rooted = good
        # but in smali Z: 0x0 = false
        repl = to_zero(body)  # false = not rooted
        if body != repl:
            out = out.replace(body, repl, 1)
            print(f"  [S3-root] {filepath}")
            count += 1

    for m in re.finditer(
        r'(\.method\s+[^\n]*getWarrantyBit[^\n]*\)I\n(?:(?!\.end method)[\s\S])*?\.end method)',
        out, re.MULTILINE
    ):
        body = m.group(0)
        repl = to_zero(body)
        if body != repl:
            out = out.replace(body, repl, 1)
            print(f"  [S3-warranty] {filepath}")
            count += 1

    if out != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(out)

    return count


def patch_dir(root: str) -> int:
    total = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if fn.endswith('.smali'):
                total += patch_file(os.path.join(dirpath, fn))
    return total


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: patch_wearable.py <decompiled_dir>')
        sys.exit(1)

    base = sys.argv[1]
    grand_total = 0

    for smali_subdir in ['smali', 'smali_classes2', 'smali_classes3',
                         'smali_classes4', 'smali_classes5']:
        path = os.path.join(base, smali_subdir)
        if os.path.isdir(path):
            print(f'\nScanning {smali_subdir} ...')
            grand_total += patch_dir(path)

    print(f'\nTotal patches applied: {grand_total}')
    if grand_total == 0:
        print('WARNING: nothing was patched — APK may use heavy obfuscation.')
        sys.exit(2)
