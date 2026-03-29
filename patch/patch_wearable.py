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

def to_true(m):  f = m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x1\n    return v0\n.end method"
def to_false(m): f = m.split('\n')[0]; return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x0\n    return v0\n.end method"

def find_methods(content, ret):
    return list(re.finditer(
        r'(\.method\s+[^\n]*\)' + re.escape(ret) + r'\n(?:(?!\.end method)[\s\S])*?\.end method)',
        content, re.MULTILINE))

def patch_file(fp, stats):
    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
        orig = f.read()
    out = orig
    count = 0
    fname = os.path.basename(fp)

    # S1: boolean methods reading Build.MANUFACTURER + "samsung"
    for m in find_methods(orig, 'Z'):
        b = m.group(0)
        if 'Landroid/os/Build;->MANUFACTURER' in b and 'samsung' in b.lower():
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s1']+=1
            print(f'  [S1] {fname} :: {b.split(chr(10))[0].strip()}')

    # S2: known compatibility method names
    for name in ['isSamsungDevice','isSamsungPhone','isSupportedPhone','isCompatiblePhone',
                 'isSupportedDevice','checkCompatibility','isPhoneSupported','isAllowedDevice',
                 'isSupportedModel','isTargetDevice','checkDeviceSupport']:
        for m in re.finditer(r'(\.method\s+[^\n]*'+re.escape(name)+r'[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
            b = m.group(0); r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s2']+=1
            print(f'  [S2:{name}] {fname}')

    # S3: Knox direct
    for m in re.finditer(r'(\.method\s+[^\n]*isDeviceRooted[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)', out, re.MULTILINE):
        b = m.group(0); r = to_false(b)
        if b != r: out = out.replace(b,r,1); count+=1; stats['s3']+=1

    # S4: boolean methods calling Knox
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if 'Lcom/samsung/android/knox/' in b:
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s4']+=1
            print(f'  [S4-Knox] {fname}')

    # S5: signature self-check
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if ('PackageInfo;->signatures' in b or 'PackageInfo;->signingInfo' in b
                or ('getPackageInfo' in b and '0x40' in b)):
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s5']+=1
            print(f'  [S5-Sig] {fname} :: {b.split(chr(10))[0].strip()}')

    # S6: boolean methods reading Build integrity fields
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if any(f in b for f in ['Landroid/os/Build;->FINGERPRINT','Landroid/os/Build;->TAGS',
                                 'Landroid/os/Build;->TYPE','release-keys']):
            r = to_true(b)
            if b != r: out = out.replace(b,r,1); count+=1; stats['s6']+=1
            print(f'  [S6-Build] {fname} :: {b.split(chr(10))[0].strip()}')

    # S7: void/any methods that do MANUFACTURER check inline
    # Find ALL methods (not just boolean) containing Build.MANUFACTURER + samsung
    for m in find_methods(out, 'V'):
        b = m.group(0)
        # Skip constructors
        first = b.split('\n')[0]
        if '<init>' in first or '<clinit>' in first:
            continue
        if 'Landroid/os/Build;->MANUFACTURER' in b and 'samsung' in b.lower():
            # Find if-eqz or if-nez after the equalsIgnoreCase/equals call
            lines = b.split('\n')
            new_lines = list(lines)
            for i, line in enumerate(lines):
                if re.search(r'invoke-virtual.*equalsIgnoreCase|invoke-virtual.*equals\b', line):
                    # look for move-result + if-*z in next 3 lines
                    for j in range(i+1, min(i+4, len(lines))):
                        if re.match(r'\s+move-result\s+v', lines[j]):
                            for k in range(j+1, min(j+3, len(lines))):
                                mo = re.match(r'(\s+)(if-eqz|if-nez)(\s+\S+,\s*)(:\S+)', lines[k])
                                if mo:
                                    # Replace the if with goto to the SUCCESS label
                                    # if-nez = jump if true (non-zero) -> jump to success
                                    # if-eqz = jump if false (zero) -> jump to error
                                    # We want to always go to success:
                                    if mo.group(2) == 'if-nez':
                                        new_lines[k] = mo.group(1) + 'goto ' + mo.group(4)
                                    else:  # if-eqz means 0=no match=error branch, we skip it
                                        new_lines[k] = mo.group(1) + '# removed-if-eqz (was error branch)'
                                    count+=1; stats['s7']+=1
                                    print(f'  [S7-VoidMfr] {fname} :: {first.strip()}')
                                    break
                            break
            new_body = '\n'.join(new_lines)
            if new_body != b:
                out = out.replace(b, new_body, 1)

    # S8: ALL non-constructor boolean methods in CertificateChecker
    if 'certificatechecker' in fname.lower():
        for m in find_methods(out, 'Z'):
            b = m.group(0)
            if '<init>' in b.split('\n')[0] or '<clinit>' in b.split('\n')[0]:
                continue
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
    stats = {f's{i}':0 for i in range(1,9)}
    total_files = total_patches = 0
    subdirs = [d for d in ['smali','smali_classes2','smali_classes3','smali_classes4','smali_classes5']
               if os.path.isdir(os.path.join(base, d))]
    print(f'Smali dirs: {subdirs}')
    for sub in subdirs:
        for dp, _, files in os.walk(os.path.join(base, sub)):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dp, fn), stats)
    print(f'\n=== Summary ===')
    print(f'Files   : {total_files}')
    print(f'Patches : {total_patches}')
    for k,v in stats.items(): print(f'  {k}: {v}')
    if total_patches == 0:
        print('WARNING: nothing patched'); sys.exit(2)
