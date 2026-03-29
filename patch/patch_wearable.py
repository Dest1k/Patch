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
def to_void(m):  f=m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    return-void\n.end method"
def to_zero(m):  f=m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x0\n    return v0\n.end method"
def to_null(m):  f=m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x0\n    return-object v0\n.end method"

def find_methods(content, ret):
    return list(re.finditer(
        r'(\.method\s+[^\n]*\)' + re.escape(ret) + r'\n(?:(?!\.end method)[\s\S])*?\.end method)',
        content, re.MULTILINE))

def is_constructor(method_first_line):
    return '<init>' in method_first_line or '<clinit>' in method_first_line


def stub_native_method(body):
    """
    Replace a 'native' method declaration with a stub that returns safe values.
    native Z -> return true
    native I -> return 0
    native V -> return-void
    native L... -> return null
    """
    first = body.split('\n')[0]
    if 'native' not in first:
        return body, False

    # Determine return type
    ret_match = re.search(r'\)([ZBSIJFDV]|L[^;]+;|\[.+)$', first.strip())
    if not ret_match:
        return body, False
    ret = ret_match.group(1)

    # Remove 'native' from the method declaration
    new_first = re.sub(r'\bnative\b\s*', '', first)

    regs = get_registers(body)  # will be 0 for native, use param count
    # Count params for register allocation
    sig_match = re.search(r'\(([^)]*)\)', first)
    param_regs = 1  # at least 1 register
    if sig_match:
        s = sig_match.group(1)
        i = 0
        while i < len(s):
            if s[i] == 'L': i = s.index(';', i) + 1; param_regs += 1
            elif s[i] == '[': i += 1; continue
            else: param_regs += 2 if s[i] in 'JD' else 1; i += 1
    if 'static' not in first:
        param_regs += 1
    regs = max(param_regs + 1, 2)

    if ret == 'Z':   body_stub = f"    .registers {regs}\n    const/4 v0, 0x1\n    return v0"
    elif ret == 'V': body_stub = f"    .registers {regs}\n    return-void"
    elif ret in ('I','S','B','C'): body_stub = f"    .registers {regs}\n    const/4 v0, 0x0\n    return v0"
    elif ret in ('J',): body_stub = f"    .registers {regs}\n    const-wide/16 v0, 0x0\n    return-wide v0"
    elif ret in ('F',): body_stub = f"    .registers {regs}\n    const/4 v0, 0x0\n    return v0"
    elif ret in ('D',): body_stub = f"    .registers {regs}\n    const-wide/16 v0, 0x0\n    return-wide v0"
    else:             body_stub = f"    .registers {regs}\n    const/4 v0, 0x0\n    return-object v0"

    new_body = f"{new_first}\n{body_stub}\n.end method"
    return new_body, True


def patch_file(fp, stats):
    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
        orig = f.read()
    out = orig
    count = 0
    fname = os.path.basename(fp)

    # S9 (highest priority): stub ALL native methods in files that load DiagMonKey
    # or that declare native methods (covers the JNI bridge class)
    if 'DiagMonKey' in orig or ('native' in orig and any(
            kw in fp for kw in ['DiagMon','diagmon','NativeLib','JniLib','SecurityNative'])):
        all_methods = re.finditer(
            r'(\.method\s+[^\n]*\n(?:(?!\.end method)[\s\S])*?\.end method)',
            out, re.MULTILINE)
        for m in all_methods:
            b = m.group(0)
            if 'native' in b.split('\n')[0]:
                new_b, changed = stub_native_method(b)
                if changed:
                    out = out.replace(b, new_b, 1); count += 1; stats['s9'] += 1
                    print(f'  [S9-DiagMonKey-native] {fname} :: {b.split(chr(10))[0].strip()}')

    # Also stub any native method whose name hints at key/auth/verify checking
    KEY_NATIVE_HINTS = ['key','auth','verify','check','valid','sign','cert','integrity','license']
    all_methods = re.finditer(
        r'(\.method\s+[^\n]*\n(?:(?!\.end method)[\s\S])*?\.end method)',
        out, re.MULTILINE)
    for m in all_methods:
        b = m.group(0)
        first = b.split('\n')[0]
        if 'native' not in first: continue
        method_name = re.search(r'\s(\w+)\(', first)
        if method_name and any(h in method_name.group(1).lower() for h in KEY_NATIVE_HINTS):
            new_b, changed = stub_native_method(b)
            if changed:
                out = out.replace(b, new_b, 1); count += 1; stats['s9'] += 1
                print(f'  [S9-NativeHint] {fname} :: {first.strip()}')

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

    # S8: all non-constructor boolean methods in CertificateChecker
    if 'certificatechecker' in fname.lower():
        for m in find_methods(out, 'Z'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]): continue
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s8']+=1
            print(f'  [S8-Cert] {fname} :: {b.split(chr(10))[0].strip()}')

    if out != orig:
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(out)
    return count


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: patch_wearable.py <smali_root>'); sys.exit(1)
    base = sys.argv[1]
    stats = {f's{i}':0 for i in range(1,10)}
    total_files = total_patches = 0
    subdirs = [d for d in ['smali','smali_classes2','smali_classes3','smali_classes4','smali_classes5']
               if os.path.isdir(os.path.join(base, d))]
    print(f'Smali dirs: {subdirs}')
    for sub in subdirs:
        for dp,_,files in os.walk(os.path.join(base,sub)):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dp,fn), stats)
    print(f'\n=== Summary ===')
    print(f'Files   : {total_files}')
    print(f'Patches : {total_patches}')
    for k,v in stats.items(): print(f'  {k}: {v}')
    if total_patches == 0:
        print('WARNING: nothing patched'); sys.exit(2)
