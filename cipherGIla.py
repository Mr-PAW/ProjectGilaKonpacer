import binascii

# cipher semua
def caesar_encrypt_text(plaintext: str, key: int) -> str:
    res = []
    for ch in plaintext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            res.append(chr((ord(ch) - ord(base) + key) % 26 + ord(base)))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_decrypt_text(ciphertext: str, key: int) -> str:
    return caesar_encrypt_text(ciphertext, (-key) % 26)

def vigenere_encrypt_text(plaintext: str, key: str) -> str:
    res = []
    keyletters = ''.join([c for c in key if c.isalpha()])
    if not keyletters:
        return plaintext
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            k = ord(keyletters[ki % len(keyletters)].lower()) - ord('a')
            res.append(chr((ord(ch) - ord(base) + k) % 26 + ord(base)))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

def vigenere_decrypt_text(ciphertext: str, key: str) -> str:
    res = []
    keyletters = ''.join([c for c in key if c.isalpha()])
    if not keyletters:
        return ciphertext
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            k = ord(keyletters[ki % len(keyletters)].lower()) - ord('a')
            res.append(chr((ord(ch) - ord(base) - k) % 26 + ord(base)))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

def xor_encrypt_text(plaintext: str, key: str) -> str:
    ptbytes = plaintext.encode('utf-8')
    keybytes = key.encode('utf-8') if key else b'\x00'
    out = bytes([ptbytes[i] ^ keybytes[i % len(keybytes)] for i in range(len(ptbytes))])
    return binascii.hexlify(out).decode()

def xor_decrypt_text(hexcipher: str, key: str) -> str:
    try:
        data = binascii.unhexlify(hexcipher)
    except Exception:
        return ''
    if not key:
        keybytes = b'\x00'
    else:
        keybytes = key.encode('utf-8')
    out = bytes([data[i] ^ keybytes[i % len(keybytes)] for i in range(len(data))])
    return out.decode('utf-8', errors='replace')

def super_encrypt_text(plaintext: str, key: str) -> str:
    # Support composite key format for super encryption so each stage can use a
    # different key. Expected composite format: 'vig=<vigenere_key>;caesar=<shift>;xor=<xor_key>'
    # If provided key doesn't match composite format, fall back to legacy behavior
    # where the same `key` is used for all stages.
    def _parse_super_key(k: str):
        if not k:
            return ('', None, '')
        # try simple parser splitting by ';' and '='
        parts = [p.strip() for p in k.split(';') if '=' in p]
        if not parts:
            return (k, None, k)
        vig = ''
        caesar = None
        xr = ''
        for p in parts:
            try:
                name, val = p.split('=', 1)
            except ValueError:
                continue
            name = name.strip().lower()
            val = val.strip()
            if name in ('vig', 'vigenere'):
                vig = val
            elif name == 'caesar':
                try:
                    caesar = int(val)
                except Exception:
                    caesar = None
            elif name in ('xor', 'xorkey'):
                xr = val
        # If caesar not specified but vig provided, leave caesar as None to derive later
        return (vig or '', caesar, xr or '')

    vig_key, caesar_key, xor_key = _parse_super_key(key)

    # Stage 1: Vigenere (use provided vig_key or legacy use of `key`)
    if vig_key:
        stage1 = vigenere_encrypt_text(plaintext, vig_key)
    else:
        stage1 = vigenere_encrypt_text(plaintext, key)

    # Stage 2: Caesar (use provided numeric caesar_key; if not provided, derive from vig_key or legacy key)
    if caesar_key is None:
        base_for_shift = vig_key if vig_key else key
        if base_for_shift:
            try:
                shift = sum(bytearray(base_for_shift.encode('utf-8'))) % 26
            except Exception:
                shift = 0
        else:
            shift = 0
    else:
        shift = caesar_key % 26
    stage2 = caesar_encrypt_text(stage1, shift)

    # Stage 3: XOR (use xor_key if present, else legacy key)
    use_xor_key = xor_key if xor_key else key
    stage3 = xor_encrypt_text(stage2, use_xor_key)
    return stage3

def super_decrypt_text(ciphertext: str, key: str) -> str:
    # Parse composite key format similar to super_encrypt_text
    def _parse_super_key(k: str):
        if not k:
            return ('', None, '')
        parts = [p.strip() for p in k.split(';') if '=' in p]
        if not parts:
            return (k, None, k)
        vig = ''
        caesar = None
        xr = ''
        for p in parts:
            try:
                name, val = p.split('=', 1)
            except ValueError:
                continue
            name = name.strip().lower()
            val = val.strip()
            if name in ('vig', 'vigenere'):
                vig = val
            elif name == 'caesar':
                try:
                    caesar = int(val)
                except Exception:
                    caesar = None
            elif name in ('xor', 'xorkey'):
                xr = val
        return (vig or '', caesar, xr or '')

    vig_key, caesar_key, xor_key = _parse_super_key(key)

    # Stage 1: XOR decrypt
    use_xor_key = xor_key if xor_key else key
    stage1 = xor_decrypt_text(ciphertext, use_xor_key)

    # Stage 2: Caesar decrypt
    if caesar_key is None:
        base_for_shift = vig_key if vig_key else key
        if base_for_shift:
            try:
                shift = sum(bytearray(base_for_shift.encode('utf-8'))) % 26
            except Exception:
                shift = 0
        else:
            shift = 0
    else:
        shift = caesar_key % 26
    stage2 = caesar_decrypt_text(stage1, shift)

    # Stage 3: Vigenere decrypt
    if vig_key:
        stage3 = vigenere_decrypt_text(stage2, vig_key)
    else:
        stage3 = vigenere_decrypt_text(stage2, key)
    return stage3

def encrypt_file_bytes(data: bytes, cipher: str, key: str) -> bytes:
    lc = (cipher or '').lower()
    if lc == 'caesar':
        try:
            k = int(key) % 256
        except:
            k = 0
        return bytes([(b + k) % 256 for b in data])
    elif lc == 'vigenere':
        if not key:
            return data
        kb = key.encode('utf-8')
        return bytes([(data[i] + kb[i % len(kb)]) % 256 for i in range(len(data))])
    elif lc == 'xor':
        if not key:
            return data
        kb = key.encode('utf-8')
        return bytes([data[i] ^ kb[i % len(kb)] for i in range(len(data))])
    else:
        return data

def decrypt_file_bytes(data: bytes, cipher: str, key: str) -> bytes:
    lc = (cipher or '').lower()
    if lc == 'caesar':
        try:
            k = int(key) % 256
        except:
            k = 0
        return bytes([(b - k) % 256 for b in data])
    elif lc == 'vigenere':
        if not key:
            return data
        kb = key.encode('utf-8')
        return bytes([(data[i] - kb[i % len(kb)]) % 256 for i in range(len(data))])
    elif lc == 'xor':
        if not key:
            return data
        kb = key.encode('utf-8')
        return bytes([data[i] ^ kb[i % len(kb)] for i in range(len(data))])
    else:
        return data