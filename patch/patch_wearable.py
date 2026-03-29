#!/usr/bin/env python3
import os, re, sys

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

def to_true(m):  f=m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x1\n    return v0\n.end method"
def to_false(m): f=m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x0\n    return v0\n.end method"

def find_methods(content, ret):
    return list(re.finditer(
        r'(\.method\s+[^\n]*\)' + re.escape(ret) + r'\n(?:(?!\.end method)[\s\S])*?\.end method)',
        content, re.MULTILINE))

def is_constructor(first_line):
    return '<init>' in first_line or '<clinit>' in first_line


def find_error_string_ids(full_dir):
    """Search decoded resources for error-related string resource IDs."""
    ids = set()
    keywords = re.compile(
        r'unauthorized|without.*author|os.*modif|modif.*os|tamper|'
        r'not_support|unsupport|incompatible|os_error|security_error|'
        r'gear_not|phone_not|device_not|knox|warranty',
        re.IGNORECASE)
    if not full_dir:
        return ids
    for root, _, files in os.walk(os.path.join(full_dir, 'res')):
        for fn in files:
            if not fn.endswith('.xml'): continue
            fp = os.path.join(root, fn)
            try:
                content = open(fp, encoding='utf-8', errors='ignore').read()
                for m in re.finditer(r'<string\s+name="([^"]+)"[^>]*>([^<]*)</string>', content):
                    name, val = m.group(1), m.group(2)
                    if keywords.search(name) or keywords.search(val):
                        ids.add(name)
                        print(f'  [STRFOUND] name={name!r} val={val[:80]!r}')
            except Exception:
                pass
    return ids


def patch_file(fp, stats, error_str_names):
    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
        orig = f.read()
    out = orig
    count = 0
    fname = os.path.basename(fp)

    # S9: stub DiagMonKey native methods
    if 'DiagMonKey' in orig:
        for m in re.finditer(r'(\.method\s+[^\n]*\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
            b = m.group(0)
            first = b.split('\n')[0]
            if 'native' not in first: continue
            ret = re.search(r'\)([ZBSIJFDV]|L[^;]+;)', first.strip())
            if not ret: continue
            rt = ret.group(1)
            new_first = re.sub(r'\bnative\b\s*', '', first)
            r = get_registers(b); r = max(r, 2)
            if rt == 'Z':   stub = f"    .registers {r}\n    const/4 v0, 0x1\n    return v0"
            elif rt == 'V': stub = f"    .registers {r}\n    return-void"
            elif rt in 'ISBCF': stub = f"    .registers {r}\n    const/4 v0, 0x0\n    return v0"
            elif rt in 'JD':    stub = f"    .registers {r}\n    const-wide/16 v0, 0x0\n    return-wide v0"
            else:               stub = f"    .registers {r}\n    const/4 v0, 0x0\n    return-object v0"
            new_b = f"{new_first}\n{stub}\n.end method"
            if b != new_b:
                out = out.replace(b, new_b, 1); count += 1; stats['s9'] += 1
                print(f'  [S9] {fname} :: {first.strip()}')

    # S1
    for m in find_methods(orig, 'Z'):
        b = m.group(0)
        if 'Landroid/os/Build;->MANUFACTURER' in b and 'samsung' in b.lower():
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s1']+=1
            print(f'  [S1] {fname} :: {b.split(chr(10))[0].strip()}')

    # S2
    for name in ['isSamsungDevice','isSamsungPhone','isSupportedPhone','isCompatiblePhone',
                 'isSupportedDevice','checkCompatibility','isPhoneSupported','isAllowedDevice',
                 'isSupportedModel','isTargetDevice','checkDeviceSupport']:
        for m in re.finditer(r'(\.method\s+[^\n]*'+re.escape(name)+r'[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
            b = m.group(0); r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s2']+=1
            print(f'  [S2:{name}] {fname}')

    # S3
    for m in re.finditer(r'(\.method\s+[^\n]*isDeviceRooted[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
        b = m.group(0); r = to_false(b)
        if b != r: out = out.replace(b,r,1); count+=1; stats['s3']+=1

    # S4
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if 'Lcom/samsung/android/knox/' in b:
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s4']+=1

    # S5
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if ('PackageInfo;->signatures' in b or 'PackageInfo;->signingInfo' in b
                or ('getPackageInfo' in b and '0x40' in b)):
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s5']+=1
            print(f'  [S5-Sig] {fname} :: {b.split(chr(10))[0].strip()}')

    # S6
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if is_constructor(b.split('\n')[0]): continue
        if any(f in b for f in ['Landroid/os/Build;->FINGERPRINT','Landroid/os/Build;->TAGS',
                                 'Landroid/os/Build;->TYPE','release-keys']):
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s6']+=1
            print(f'  [S6-Build] {fname} :: {b.split(chr(10))[0].strip()}')

    # S8
    if 'certificatechecker' in fname.lower():
        for m in find_methods(out, 'Z'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]): continue
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s8']+=1
            print(f'  [S8-Cert] {fname} :: {b.split(chr(10))[0].strip()}')

    # S10: patch methods that reference error string resource names found in res/
    if error_str_names:
        for m in find_methods(out, 'V'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]): continue
            for name in error_str_names:
                if name in b:
                    # Make the void method return immediately
                    regs = get_registers(b)
                    first = b.split('\n')[0]
                    new_b = f"{first}\n    .registers {regs}\n    return-void\n.end method"
                    if b != new_b:
                        out = out.replace(b, new_b, 1); count += 1; stats['s10'] += 1
                        print(f'  [S10-ErrStr:{name}] {fname} :: {first.strip()}')
                    break

    if out != orig:
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(out)
    return count


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: patch_wearable.py <smali_root> [full_decode_dir]'); sys.exit(1)
    base = sys.argv[1]
    full_dir = sys.argv[2] if len(sys.argv) > 2 else None

    stats = {f's{i}':0 for i in range(1,11)}
    total_files = total_patches = 0

    print('=== Searching for error strings in resources ===')
    error_str_names = find_error_string_ids(full_dir)
    print(f'Error string names found: {error_str_names}')

    subdirs = [d for d in ['smali','smali_classes2','smali_classes3','smali_classes4','smali_classes5']
               if os.path.isdir(os.path.join(base, d))]
    print(f'\nSmali dirs: {subdirs}')

    for sub in subdirs:
        for dp,_,files in os.walk(os.path.join(base,sub)):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dp,fn), stats, error_str_names)

    print(f'\n=== Summary ===')
    print(f'Files   : {total_files}')
    print(f'Patches : {total_patches}')
    for k,v in stats.items(): print(f'  {k}: {v}')
    if total_patches == 0:
        print('WARNING: nothing patched'); sys.exit(2)
