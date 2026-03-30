#!/usr/bin/env python3
import os, re, sys


def count_min_registers(first_line):
    """Minimum registers = param_registers + 1 local (for our return value)."""
    is_static = 'static' in first_line
    sig = re.search(r'\(([^)]*)\)', first_line)
    params = 0
    if sig:
        s, i = sig.group(1), 0
        while i < len(s):
            if s[i] == 'L':
                end = s.find(';', i)
                if end == -1: break
                i = end + 1
            elif s[i] == '[':
                i += 1
            else:
                params += 2 if s[i] in 'JD' else 1
                i += 1
    if not is_static:
        params += 1  # 'this'
    return params + 1  # +1 for v0 local


def get_registers(method):
    first_line = method.split('\n')[0]
    minimum = count_min_registers(first_line)
    m = re.search(r'\.registers\s+(\d+)', method)
    if m:
        return max(int(m.group(1)), minimum)
    m = re.search(r'\.locals\s+(\d+)', method)
    if m:
        sig = re.search(r'\(([^)]*)\)', first_line)
        params = 0
        if sig:
            s, i = sig.group(1), 0
            while i < len(s):
                if s[i] == 'L':
                    end = s.find(';', i)
                    if end == -1: break
                    i = end + 1
                elif s[i] == '[':
                    i += 1
                else:
                    params += 2 if s[i] in 'JD' else 1
                    i += 1
        if 'static' not in first_line:
            params += 1
        return max(int(m.group(1)) + params, minimum)
    return minimum


def to_true(m):
    f = m.split('\n')[0]
    return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x1\n    return v0\n.end method"


def to_false(m):
    f = m.split('\n')[0]
    return f"{f}\n    .registers {get_registers(m)}\n    const/4 v0, 0x0\n    return v0\n.end method"


def to_void(m):
    f = m.split('\n')[0]
    return f"{f}\n    .registers {get_registers(m)}\n    return-void\n.end method"


def find_methods(content, ret):
    return list(re.finditer(
        r'(\.method\s+[^\n]*\)' + re.escape(ret) + r'\n(?:(?!\.end method)[\s\S])*?\.end method)',
        content, re.MULTILINE))


def is_constructor(first_line):
    return '<init>' in first_line or '<clinit>' in first_line


def get_error_resource_ids(full_dir):
    """Parse public.xml to get hex resource IDs for error-related strings."""
    id_to_name = {}
    if not full_dir:
        return id_to_name

    name_keywords = re.compile(
        r'unauthori|without.*author|os.*modif|modif.*os|tamper|'
        r'not_support|unsupport|incompatible|os_error|security_error|'
        r'gear_not|phone_not|device_not|knox|warranty|not_allow|blocked|'
        r'modify|changed|invalid_device|wrong_device|revok|illegal|integ|'
        r'custom_binary|custombinary|binary_error|custom_os|phone_os',
        re.IGNORECASE)

    public_xml = os.path.join(full_dir, 'res', 'values', 'public.xml')
    if os.path.exists(public_xml):
        content = open(public_xml, encoding='utf-8', errors='ignore').read()
        for m in re.finditer(
                r'<public\s+type="string"\s+name="([^"]+)"\s+id="(0x[0-9a-fA-F]+)"',
                content):
            name, rid = m.group(1), m.group(2)
            if name_keywords.search(name):
                hex_val = hex(int(rid, 16))
                id_to_name[hex_val] = name
                print(f'  [RESID] {name} -> {hex_val}')
    else:
        print(f'  [WARN] public.xml not found at {public_xml}')

    print(f'Total error resource IDs found: {len(id_to_name)}')
    return id_to_name


def patch_file(fp, stats, error_res_ids):
    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
        orig = f.read()
    out = orig
    count = 0
    fname = os.path.basename(fp)
    fname_lower = fname.lower()

    # S9: stub DiagMonKey native methods
    if 'DiagMonKey' in orig:
        for m in re.finditer(
                r'(\.method\s+[^\n]*\n(?:(?!\.end method)[\s\S])*?\.end method)',
                out, re.MULTILINE):
            b = m.group(0)
            first = b.split('\n')[0]
            if 'native' not in first:
                continue
            ret = re.search(r'\)([ZBSIJFDV]|L[^;]+;)', first.strip())
            if not ret:
                continue
            rt = ret.group(1)
            new_first = re.sub(r'\bnative\b\s*', '', first)
            r = get_registers(b)
            if rt == 'Z':   stub = f"    .registers {r}\n    const/4 v0, 0x1\n    return v0"
            elif rt == 'V': stub = f"    .registers {r}\n    return-void"
            elif rt in 'ISBCF': stub = f"    .registers {r}\n    const/4 v0, 0x0\n    return v0"
            elif rt in 'JD':    stub = f"    .registers {r}\n    const-wide/16 v0, 0x0\n    return-wide v0"
            else:               stub = f"    .registers {r}\n    const/4 v0, 0x0\n    return-object v0"
            new_b = f"{new_first}\n{stub}\n.end method"
            if b != new_b:
                out = out.replace(b, new_b, 1)
                count += 1
                stats['s9'] += 1
                print(f'  [S9] {fname} :: {first.strip()}')

    # S1: Build.MANUFACTURER == "samsung" checks
    for m in find_methods(orig, 'Z'):
        b = m.group(0)
        if 'Landroid/os/Build;->MANUFACTURER' in b and 'samsung' in b.lower():
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s1'] += 1
                print(f'  [S1] {fname} :: {b.split(chr(10))[0].strip()}')

    # S2: device compatibility check methods by name
    for name in ['isSamsungDevice', 'isSamsungPhone', 'isSupportedPhone', 'isCompatiblePhone',
                 'isSupportedDevice', 'checkCompatibility', 'isPhoneSupported', 'isAllowedDevice',
                 'isSupportedModel', 'isTargetDevice', 'checkDeviceSupport', 'isSamsungGalaxy',
                 'isGalaxyDevice', 'isSamsungProduct', 'checkPhoneCompatibility']:
        pat = r'(\.method\s+[^\n]*' + re.escape(name) + r'[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)'
        for m in re.finditer(pat, out, re.MULTILINE):
            b = m.group(0)
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s2'] += 1
                print(f'  [S2:{name}] {fname}')

    # S3: root/bootloader detection
    for m in re.finditer(
            r'(\.method\s+[^\n]*(?:isDeviceRooted|isRooted|isBootloaderUnlocked|checkRoot)[^\n]*\)Z\n(?:(?!\.end method)[\s\S])*?\.end method)',
            out, re.MULTILINE):
        b = m.group(0)
        r = to_false(b)
        if b != r:
            out = out.replace(b, r, 1)
            count += 1
            stats['s3'] += 1
            print(f'  [S3-Root] {fname} :: {b.split(chr(10))[0].strip()}')

    # S4: Knox boolean methods
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if 'Lcom/samsung/android/knox/' in b:
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s4'] += 1
                print(f'  [S4-Knox] {fname} :: {b.split(chr(10))[0].strip()}')

    # S5: signature/package verification
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if is_constructor(b.split('\n')[0]):
            continue
        sig_check = (
            'PackageInfo;->signatures' in b
            or 'PackageInfo;->signingInfo' in b
            or ('getPackageInfo' in b and ('signatures' in b.lower() or '0x40' in b or '0x44' in b or '0x4000000' in b))
            or ('Signature' in b and ('digest' in b.lower() or 'hash' in b.lower()
                                       or 'match' in b.lower() or 'equal' in b.lower() or 'verify' in b.lower()))
        )
        if sig_check:
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s5'] += 1
                print(f'  [S5-Sig] {fname} :: {b.split(chr(10))[0].strip()}')

    # S6: Build integrity fields in boolean methods
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if is_constructor(b.split('\n')[0]):
            continue
        if any(f in b for f in ['Landroid/os/Build;->FINGERPRINT', 'Landroid/os/Build;->TAGS',
                                 'Landroid/os/Build;->TYPE', 'release-keys']):
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s6'] += 1
                print(f'  [S6-Build] {fname} :: {b.split(chr(10))[0].strip()}')

    # S8: boolean methods in specific security classes only
    is_security_class = bool(re.search(
        r'certificatechecker|certificaterevok|'
        r'sakverif|gakverif|verificationmanager|'
        r'(^|[^a-z])verifier($|[^a-z])|verifierinterface|'
        r'packagesign|signatureverif|trustmanager|certpinning|certificatepinn',
        fname_lower))
    if is_security_class:
        for m in find_methods(out, 'Z'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]):
                continue
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s8'] += 1
                print(f'  [S8-SecClass] {fname} :: {b.split(chr(10))[0].strip()}')

    # S11: CertificateRevocationStatus
    if re.search(r'revok|revocation', fname_lower):
        for m in find_methods(out, 'Z'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]):
                continue
            r = to_true(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s11'] += 1
                print(f'  [S11-Revoc] {fname} :: {b.split(chr(10))[0].strip()}')
        for m in find_methods(out, 'V'):
            b = m.group(0)
            if is_constructor(b.split('\n')[0]):
                continue
            if 'throw' in b or 'Exception' in b:
                r = to_void(b)
                if b != r:
                    out = out.replace(b, r, 1)
                    count += 1
                    stats['s11'] += 1
                    print(f'  [S11-RevocVoid] {fname} :: {b.split(chr(10))[0].strip()}')

    # S12: Knox custom binary / warranty check
    for m in find_methods(out, 'Z'):
        b = m.group(0)
        if is_constructor(b.split('\n')[0]):
            continue
        if ('warranty_bit' in b or 'custom_binary' in b.lower()
                or 'getCustomBinaryStatus' in b
                or 'getWarrantyStatus' in b
                or 'isCustomKernel' in b
                or 'KnoxCustomManager' in b):
            r = to_false(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s12'] += 1
                print(f'  [S12-CustomBin] {fname} :: {b.split(chr(10))[0].strip()}')
    for m in find_methods(out, 'V'):
        b = m.group(0)
        if is_constructor(b.split('\n')[0]):
            continue
        if ('warranty_bit' in b or 'getCustomBinaryStatus' in b
                or 'getWarrantyStatus' in b or 'KnoxCustomManager' in b):
            r = to_void(b)
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s12'] += 1
                print(f'  [S12-CustomBinVoid] {fname} :: {b.split(chr(10))[0].strip()}')

    # S10: patch methods referencing error string resource IDs
    if error_res_ids:
        all_methods = list(re.finditer(
            r'(\.method\s+[^\n]*\n(?:(?!\.end method)[\s\S])*?\.end method)',
            out, re.MULTILINE))
        for m in all_methods:
            b = m.group(0)
            first = b.split('\n')[0]
            if is_constructor(first):
                continue
            matched_name = None
            for rid, rname in error_res_ids.items():
                if re.search(r'const[^\n]*' + re.escape(rid), b, re.IGNORECASE):
                    matched_name = rname
                    break
            if not matched_name:
                continue
            ret_match = re.search(r'\)([ZBSIJFDV]|L[^;]+;)\s*$', first.strip())
            if not ret_match:
                continue
            rt = ret_match.group(1)
            if rt == 'V':
                r = to_void(b)
            elif rt == 'Z':
                r = to_true(b)
            else:
                continue
            if b != r:
                out = out.replace(b, r, 1)
                count += 1
                stats['s10'] += 1
                print(f'  [S10-ResID:{matched_name}] {fname} :: {first.strip()}')

    if out != orig:
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(out)
    return count


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: patch_wearable.py <smali_root> [full_decode_dir]')
        sys.exit(1)
    base = sys.argv[1]
    full_dir = sys.argv[2] if len(sys.argv) > 2 else None

    stats = {f's{i}': 0 for i in range(1, 13)}
    total_files = total_patches = 0

    print('=== Searching for error resource IDs ===')
    error_res_ids = get_error_resource_ids(full_dir)

    subdirs = [d for d in ['smali', 'smali_classes2', 'smali_classes3', 'smali_classes4', 'smali_classes5']
               if os.path.isdir(os.path.join(base, d))]
    print(f'\nSmali dirs: {subdirs}')

    for sub in subdirs:
        for dp, _, files in os.walk(os.path.join(base, sub)):
            for fn in files:
                if fn.endswith('.smali'):
                    total_files += 1
                    total_patches += patch_file(os.path.join(dp, fn), stats, error_res_ids)

    print(f'\n=== Summary ===')
    print(f'Files   : {total_files}')
    print(f'Patches : {total_patches}')
    for k, v in stats.items():
        print(f'  {k}: {v}')
    if total_patches == 0:
        print('WARNING: nothing patched')
        sys.exit(2)
