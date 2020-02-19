import argparse
import base64
import math

import gmpy2 as gmpy2
from Crypto.PublicKey import RSA

parser = argparse.ArgumentParser(description='RSA Common modulus attack')
required_named = parser.add_argument_group('required named arguments')
required_named.add_argument('-p1', '--pub1', help='First public key', required=True)
required_named.add_argument('-p2', '--pub2', help='Second public key', required=True)
required_named.add_argument('-m1', '--msg1', help='First ciphertext', required=True)
required_named.add_argument('-m2', '--msg2', help='Second ciphertext', required=True)


def extended_euclidean(e1, e2):
    g, a, b = gmpy2.gcdext(e1, e2)
    print("check:", g)
    return a, b


def decode(a, b, c1, c2, pkey1, pkey2):
    m1 = pow(c1, a, pkey1.n)
    print(gmpy2.invert(c2, pkey1.n))
    m2 = pow(c2, b, pkey1.n)
    plain = m1 * m2 % pkey1.n
    mes = gmpy2.to_binary(plain)
    print(mes.decode("utf-8"))



def attack(pkey1, pkey2, msg1, msg2):
    if pkey1.n != pkey1.n:
        raise ValueError("Not Common Modulus")
    if math.gcd(pkey1.e, pkey2.e) != 1:
        raise ValueError("Exponents e1 and e2 must be coprime")
    a, b = extended_euclidean(pkey1.e, pkey2.e)
    decode(a, b, msg1, msg2, pkey1, pkey2)


def main():
    args = parser.parse_args()
    print("[+] Started attack")
    #try:
    pkey1 = RSA.importKey(open(args.pub1, 'r').read())
    pkey2 = RSA.importKey(open(args.pub2, 'r').read())
    msg1 = open(args.msg1, 'r').read()
    msg2 = open(args.msg2, 'r').read()
    data1 = base64.b64decode(msg1)
    data2 = base64.b64decode(msg2)
    data1 = int.from_bytes(data1, byteorder='big')
    data2 = int.from_bytes(data2, byteorder='big')
    print("data2", data2)
    ris = attack(pkey1, pkey2, data1, data2)


if __name__ == "__main__":
    main()
