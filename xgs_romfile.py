#!/usr/bin/env python3
"""Stock XGS050: xponsn -> DD -> RSA PEM; decrypt/encrypt web ROMFILE backups.

Requires only PyCryptodome. No OpenSSL command, firmware files, or emulation.
"""
import argparse
import base64
import hashlib
import hmac
import math
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
MATERIAL = bytes.fromhex('3cb8c0e21bcb1fd824cc6d17f47792bb6995771c829bbea840bdfaba15d942b77bc22d9419517aa52535119c94d753e569c81b2fcd793ec8bb304fa6683cc86d')


def device_dd(sn):
    sn = sn.rstrip(' \t\r\n')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', sn):
        raise ValueError('xponsn must be 1-32 ASCII letters, digits, underscores or hyphens')
    digest = hmac.new(MATERIAL, sn.encode('ascii'), hashlib.sha256).digest()
    n, chars = int.from_bytes(digest, 'big'), ''
    while n:
        n, rem = divmod(n, 57)
        chars = ALPHABET[rem] + chars
    return ('2' * (len(digest) - len(digest.lstrip(b'\0'))) + chars)[:20]


class SeedStream:
    def __init__(self, seed):
        self.seed, self.counter, self.buffer = seed, 0, b''

    def read(self, size):
        while len(self.buffer) < size:
            self.buffer += hashlib.sha256(self.seed + self.counter.to_bytes(8, 'big')).digest()
            self.counter += 1
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def below(self, limit):
        bits = limit.bit_length()
        for _ in range(99):
            value = int.from_bytes(self.read((bits + 7) // 8), 'big') & ((1 << bits) - 1)
            if value < limit:
                return value
        raise ValueError('RSA random range exhausted')


def small_primes():
    sieve = bytearray(b'\1') * 17864
    sieve[:2] = b'\0\0'
    for n in range(2, math.isqrt(len(sieve) - 1) + 1):
        if sieve[n]:
            sieve[n*n::n] = b'\0' * len(sieve[n*n::n])
    return [n for n, prime in enumerate(sieve) if prime]


PRIMES = small_primes()[1:]  # The first 2048 primes, excluding 2.


def openssl_prime(stream):
    """1024-bit prime, matching OpenSSL 1.1.1b's sieve and five MR rounds."""
    while True:
        candidate = int.from_bytes(stream.read(128), 'big') | (3 << 1022) | 1
        remainders = [candidate % p for p in PRIMES]
        delta = 0
        while any((r + delta) % p <= 1 for r, p in zip(remainders, PRIMES)):
            delta += 2
        candidate += delta
        if candidate.bit_length() != 1024:
            continue
        odd, powers = candidate - 1, 0
        while not odd & 1:
            odd >>= 1
            powers += 1
        for _ in range(5):
            witness = pow(stream.below(candidate - 3) + 2, odd, candidate)
            if witness in (1, candidate - 1):
                continue
            for _ in range(powers - 1):
                witness = pow(witness, 2, candidate)
                if witness == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


def rsa_from_seed(seed):
    if len(seed) != 32:
        raise ValueError('RSA seed must contain exactly 32 bytes')
    stream, factors = SeedStream(seed), []
    while len(factors) < 2:
        prime = openssl_prime(stream)
        if prime not in factors and math.gcd(prime - 1, 65537) == 1:
            factors.append(prime)
    p, q = sorted(factors, reverse=True)
    return RSA.construct((p*q, 65537, pow(65537, -1, (p-1)*(q-1)), p, q))


def device_key(sn):
    dd = device_dd(sn)
    return dd, rsa_from_seed(hashlib.sha256(dd.encode('ascii')).digest())


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length()+7)//8, 'big')
    if size >= 128:
        length = bytes([128+len(length)]) + length
    return bytes([tag]) + length + value


def sequence(*values):
    return der(0x30, b''.join(values))


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')
    return der(2, (b'\0' if raw[0] & 128 else b'') + raw)


def oid(hex_value):
    return der(6, bytes.fromhex(hex_value))


RSA_OID = oid('2a864886f70d010101')
RSA_ALGORITHM = sequence(RSA_OID, b'\x05\0')
SIGN_ALGORITHM = sequence(oid('2a864886f70d01010b'), b'\x05\0')
DATA_OID = oid('2a864886f70d010701')
ENVELOPED_OID = oid('2a864886f70d010703')
AES256_OID = oid('60864801650304012a')
NAME = sequence(der(0x31, sequence(oid('550403'), der(12, b'ed-romfile'))))


def pem(label, data):
    body = base64.b64encode(data)
    return (f'-----BEGIN {label}-----\n'.encode() +
            b'\n'.join(body[i:i+64] for i in range(0, len(body), 64)) +
            f'\n-----END {label}-----\n'.encode())


def certificate(key, now=None):
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    def date(value):
        return der(23 if value.year < 2050 else 24,
                   value.strftime('%y%m%d%H%M%SZ' if value.year < 2050 else '%Y%m%d%H%M%SZ').encode())
    validity = sequence(date(now), date(now + timedelta(seconds=3153600000)))
    tbs = sequence(der(0xa0, integer(2)), integer(1), SIGN_ALGORITHM,
                   NAME, validity, NAME, key.public_key().export_key(format='DER'))
    signature = pkcs1_15.new(key).sign(SHA256.new(tbs))
    return pem('CERTIFICATE', sequence(tbs, SIGN_ALGORITHM, der(3, b'\0'+signature)))


def fields(data):
    result, pos = [], 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise ValueError('Truncated DER header')
        tag, length = data[pos:pos+2]
        pos += 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or pos + count > len(data):
                raise ValueError('Invalid DER length')
            length = int.from_bytes(data[pos:pos+count], 'big')
            pos += count
        end = pos + length
        if end > len(data):
            raise ValueError('Truncated DER content')
        result.append((tag, data[pos:end]))
        pos = end
    return result


def expect(field, tag):
    if field[0] != tag:
        raise ValueError(f'Unexpected DER tag: {field[0]:#x}, expected {tag:#x}')
    return field[1]


def require_romfile(data):
    if b'<ROMFILE' not in data or b'</ROMFILE>' not in data:
        raise ValueError('Input does not contain a complete ROMFILE document')


def decrypt_romfile(data, key):
    top = fields(data)
    if len(top) != 1:
        raise ValueError('Expected one DER PKCS#7 object')
    content = fields(expect(top[0], 0x30))
    if der(*content[0]) != ENVELOPED_OID:
        raise ValueError('Expected PKCS#7 EnvelopedData')
    envelope = fields(expect(fields(expect(content[1], 0xa0))[0], 0x30))
    recipients = fields(expect(envelope[1], 0x31))
    encrypted = fields(expect(envelope[2], 0x30))
    if der(*encrypted[0]) != DATA_OID:
        raise ValueError('Unsupported PKCS#7 content type')
    algorithm = fields(expect(encrypted[1], 0x30))
    if der(*algorithm[0]) != AES256_OID:
        raise ValueError('Expected AES-256-CBC')
    iv, ciphertext = expect(algorithm[1], 4), expect(encrypted[2], 0x80)
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError('Invalid AES-CBC parameters')
    for recipient in recipients:
        info = fields(expect(recipient, 0x30))
        if der(*fields(expect(info[2], 0x30))[0]) != RSA_OID:
            continue
        sentinel = os.urandom(32)
        session = PKCS1_v1_5.new(key).decrypt(expect(info[3], 4), sentinel, expected_pt_len=32)
        if hmac.compare_digest(session, sentinel):
            continue
        try:
            plain = unpad(AES.new(session, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
        except ValueError:
            continue
        require_romfile(plain)
        return plain
    raise ValueError('Cannot decrypt: xponsn/default DD does not match this backup')


def encrypt_romfile(plain, key):
    require_romfile(plain)
    session, iv = os.urandom(32), os.urandom(16)
    encrypted_key = PKCS1_v1_5.new(key.public_key()).encrypt(session)
    recipient = sequence(integer(0), sequence(NAME, integer(1)), RSA_ALGORITHM,
                         der(4, encrypted_key))
    ciphertext = AES.new(session, AES.MODE_CBC, iv).encrypt(pad(plain, 16))
    encrypted = sequence(DATA_OID, sequence(AES256_OID, der(4, iv)), der(0x80, ciphertext))
    result = sequence(ENVELOPED_OID,
                      der(0xa0, sequence(integer(0), der(0x31, recipient), encrypted)))
    if len(result) > 0x3ff00:
        raise ValueError('Encrypted ROMFILE exceeds the web restore limit of 261888 bytes')
    return result


def write_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    path.chmod(0o600)


def save_keys(folder, dd, key):
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    write_private(folder/'dd.txt', dd.encode('ascii')+b'\n')
    write_private(folder/'romfile_encrypt_privatekey.pem', key.export_key(pkcs=8)+b'\n')
    write_private(folder/'romfile_encrypt_cert.pem', certificate(key))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('keys', 'decrypt', 'pack'):
        sub = commands.add_parser(command)
        sub.add_argument('--sn', required=True, help='Modem xponsn')
        if command == 'keys':
            sub.add_argument('-o', '--output', type=Path, required=True, help='DD/PEM directory')
        else:
            sub.add_argument('input', type=Path, help='Backup .cfg' if command == 'decrypt' else 'Edited ROMFILE XML')
            sub.add_argument('-o', '--output', type=Path, required=True)
            sub.add_argument('--keys-dir', type=Path, help='DD/PEM directory; defaults beside output')
    args = parser.parse_args()
    try:
        if args.command != 'keys' and args.input.resolve() == args.output.resolve():
            raise ValueError('Choose a different output path to preserve the input')
        dd, key = device_key(args.sn)
        folder = args.output if args.command == 'keys' else args.keys_dir or args.output.parent/f'keys-{args.sn.rstrip()}'
        if args.command != 'keys':
            source = args.input.read_bytes()
            result = decrypt_romfile(source, key) if args.command == 'decrypt' else encrypt_romfile(source, key)
            write_private(args.output, result)
            print(f'{args.command}: {args.output} ({len(result)} bytes)')
        save_keys(folder, dd, key)
        print(f'DD/PEM: {folder}')
    except (OSError, ValueError, IndexError, TypeError) as exc:
        parser.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()

