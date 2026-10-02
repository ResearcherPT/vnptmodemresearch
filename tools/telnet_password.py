#!/usr/bin/env python3
import argparse
import hashlib
import hmac

SN_PEPPER = (
    b"ThqIwPTV2ckA4fb8QfrwxSjO6w6BFktrYpQhvlQmasdKDAYbUqoDR3ON5V1Jnyc1"
)
BASE57_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base57_encode(data: bytes) -> str:
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    digits = []

    while number:
        number, remainder = divmod(number, 57)
        digits.append(BASE57_ALPHABET[remainder])

    return BASE57_ALPHABET[0] * leading_zeros + "".join(reversed(digits))


def telnet_password_from_sn(sn: str) -> str:
    digest = hmac.new(SN_PEPPER, sn.encode(), hashlib.sha256).digest()
    return base57_encode(digest)[:20]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tính Telnet password từ GPON SN"
    )
    parser.add_argument(
        "sn",
        nargs="?",
        help="GPON SN, toàn bộ phải viết hoa."
    )
    args = parser.parse_args()

    if args.sn is None:
        parser.print_usage()
        print("ví dụ: python telnet_password.py VNPT0123ABCD")
        return

    print(telnet_password_from_sn(args.sn))


if __name__ == "__main__":
    main()