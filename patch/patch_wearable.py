#!/usr/bin/env python3
import os, re, sys

# ---------- helpers ----------

def get_registers(method):
    m = re.search(r'\.registers\s+(\d+)', method)
    if m: return max(int(m.group(1)), 1)
    m = re.search(r'\.locals\s+(\d+)', method)
    if m:
        sig = re.search(r'\(([^)]*)\)', method.split('\n')[0])
        params = 0
        if sig:
            s, i = sig.group(1), 0
            while i < len(s):
                if s[i] == 'L': i = s.index(';', i) + 1
                elif s[i] == '[': i += 1; continue
                else: params += 2 if s[i] in 'JD' else 1; i += 1
        return max(int(m.group(1)) + params + (0 if 'static' in method.split('\n')[0] else 1), 1)
    return 2

def to_true(method):
    f = method.split('\n')[0]
    return f"{f}\n    .registers {get_registers(method)}\n    const/4 v0, 0x1\n    return v0\n.end method"

def to_false(method):
    f = method.split('\n')[0]
    return f"{f}\n    .registers {get_registers(method)}\n    const/4 v0, 0x0\n    return v0\n.end method"

def to_void(method):
    f = method.split('\n')[0]
    return f"{f}\n    .registers {get_registers(method)}\n    return-void\n.end method"

def find_methods(content, ret):
    return list(re.finditer(
        r'(\.method\s+[^\n]*\)' + re.escape(ret) + r'\n(?:(?!\.end method)[\s\S])*?\.end method)',
        content, re.MULTILINE))

# Patch if-eqz/if-nez that leads to error branch after a boolean check.
# Removes the condition so code always falls through to success.
def remove_branch_after(body, trigger_pattern):
    """
    Find trigger_pattern, then find the next if-eqz or if-nez after a move-result,
    and replace it with a comment (nop effectively, keeps labels intact).
    """
    lines = body.split('\n')
    result = lines[:]
    i = 0
    changed = False
    while i < len(lines):
        if re.search(trigger_pattern, lines[i]):
            # Look ahead for move-result + if-*z
            j = i + 1
            while j < min(i + 8, len(lines)):
                if re.match(r'\s+move-result\s+', lines[j]):
                    k = j + 1
                    while k < min(j + 4, len(lines)):
                        if re.match(r'\s+if-(?:eqz|nez)\s+', lines[k]):
                            result[k] = '    # patched-branch-removed (was: ' + lines[k].strip() + ')'
                            changed = True
                            break
                        k += 1
                    break
                j += 1
        i += 1
    return '\n'.join(result), changed

# ---------- patch file ----------

def patch_file(fp, stats):
    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
        orig = f.read()
    out = orig
    count = 0

    # S1: boolean methods reading Build.MANUFACTURER + "samsung"
    for m in find_methods(orig, 'Z'):
        b = m.group(0)
        if 'Landroid/os/Build;->MANUFACTURER' in b and 'samsung' in b.lower():
            r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s1'] += 1
            print(f'  [S1] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')

    # S2: known method names
    for name in ['isSamsungDevice','isSamsungPhone','isSupportedPhone','isCompatiblePhone',
                  'isSupportedDevice','checkCompatibility','isPhoneSupported','isAllowedDevice',
                  'isSupportedModel','isTargetDevice','checkDeviceSupport']:
        for m in re.finditer(r'(\.method\s+[^\n]*' + re.escape(name) + r'[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
            b = m.group(0); r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s2'] += 1
            print(f'  [S2:{name}] {os.path.basename(fp)}')

    # S3: Knox direct
    for m in re.finditer(r'(\.method\s+[^\n]*isDeviceRooted[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
        b = m.group(0); r = to_false(b)
        if b != r: out = out.replace(b, r, 1); count += 1; stats['s3'] += 1
    for m in re.finditer(r'(\.method\s+[^\n]*getWarrantyBit[^\n]*\)I\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
        b = m.group(0); r = to_true(b)  # 0 means no warranty void
        if b != r: out = out.replace(b, r, 1); count += 1; stats['s3'] += 1

    # S4: boolean methods calling Knox
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if 'Lcom/samsung/android/knox/' in b:
            r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s4'] += 1
            print(f'  [S4-Knox] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')

    # S5: signature checks
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if ('PackageInfo;->signatures' in b or 'PackageInfo;->signingInfo' in b
                or ('getPackageInfo' in b and '0x40' in b)):
            r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s5'] += 1
            print(f'  [S5-Sig] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')

    # S6: boolean methods reading Build integrity fields
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if any(f in b for f in ['Landroid/os/Build;->FINGERPRINT','Landroid/os/Build;->TAGS',
                                  'Landroid/os/Build;->TYPE','ro.boot.verifiedbootstate',
                                  'ro.debuggable','ro.secure']):
            r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s6'] += 1
            print(f'  [S6-Build] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')

    # S7: patch if-branch in VOID methods checking Build.TAGS / ro.boot.verifiedbootstate
    # Red Magic likely has non-"release-keys" Build.TAGS which triggers the error
    BUILD_TRIGGERS = [
        r'sget-object\s+\S+,\s+Landroid/os/Build;->TAGS',
        r'sget-object\s+\S+,\s+Landroid/os/Build;->FINGERPRINT',
        r'sget-object\s+\S+,\s+Landroid/os/Build;->TYPE',
        r'const-string\s+\S+,\s+"release-keys"',
        r'const-string\s+\S+,\s+"user"',
    ]
    for m in find_methods(out, 'V'):
        b = m.group(0)
        for pat in BUILD_TRIGGERS:
            if re.search(pat, b):
                new_b, changed = remove_branch_after(b, pat)
                if changed:
                    out = out.replace(b, new_b, 1); count += 1; stats['s7'] += 1
                    print(f'  [S7-VoidBranch] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')
                    b = new_b  # apply further patches on updated body

    # S8: ALL boolean methods in security-related files
    sec_keywords = ['certificate','certificatechecker','securitychecker','integritycheck',
                    'devicecheck','authcheck','platformcheck','compatibilitycheck']
    fname_lower = os.path.basename(fp).lower()
    if any(k in fname_lower for k in sec_keywords):
        for m in find_methods(out, 'Z'):
            b = m.group(0); r = to_true(b)
            if b != r: out = out.replace(b, r, 1); count += 1; stats['s8'] += 1
            print(f'  [S8-SecFile] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')
        # Also patch void methods that might throw on failure
        for m in find_methods(out, 'V'):
            b = m.group(0)
            if ('throw' in b or 'Exception' in b) and 'checkSignature' in b or 'verify' in b.lower():
                r = to_void(b)
                if b != r: out = out.replace(b, r, 1); count += 1; stats['s8'] += 1
                print(f'  [S8-SecVoid] {os.path.basename(fp)} :: {b.split(chr(10))[0].strip()}')

    if out != orig:
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(out)
    return count


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: patch_wearable.py <smali_root>'); sys.exit(1)

    base = sys.argv[1]
    stats = {f's{i}': 0 for i in range(1, 9)}
    total_files = total_patches = 0

    subdirs = [d for d in ['smali','smali_classes2','smali_classes3','smali_classes4','smali_classes5']
               if os.path.isdir(os.path.join(base, d))]
    print(f'Smali dirs: {subdirs}')

    for sub in subdirs:
        for dirpath, _, files in os.walk(os.path.join(base, sub)):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dirpath, fn), stats)

    print(f'\n=== Summary ===')
    print(f'Files    : {total_files}')
    print(f'Patches  : {total_patches}')
    for k, v in stats.items():
        print(f'  {k}: {v}')
    if total_patches == 0:
        print('WARNING: nothing patched'); sys.exit(2)
