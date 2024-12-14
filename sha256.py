from bitstring import BitArray

def rotr(a: int, n: int) -> int:
    return add32(a >> n, a << (32 - n))

def shr(a: int, n: int) -> int:
    return a >> n

def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)

def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def add32(*args: list[int]):
    return sum(args) % (2 ** 32)

def sha256(message: bytes) -> bytes:
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    initial_length = len(message)

    if initial_length >= 2 ** 64:
        raise ValueError("Message exceeds length of 2 to the 64")

    # Add padding
    remainder_bytes = (initial_length + 8) % 64
    filler_bytes = 64 - remainder_bytes
    zero_bytes = filler_bytes - 1
    encoded_bit_length = (8 * initial_length).to_bytes(8)
    message += b"\x80" + b"\0" * zero_bytes + encoded_bit_length
    
    H = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ]

    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        words = []
        for x in range(0, len(block), 4):
            word = int.from_bytes(block[x: x + 4])
            words.append(word)
        for x in range(16, 64):
            words.append(
                add32(sigma1(words[x - 2]), words[x - 7], sigma0(words[x - 15]), words[x - 16])
            )

        a, b, c, d, e, f, g, h = H

        for x in range(64):
            T1 = add32(h, Sigma1(e), ch(e, f, g), K[x], words[x])
            T2 = add32(Sigma0(a), maj(a, b, c))
            h = g
            g = f
            f = e
            e = add32(d, T1)
            d = c
            c = b
            b = a
            a = add32(T1, T2)

        for x, val in enumerate((a, b, c, d, e, f, g, h)):
            H[x] = add32(H[x], val)

    return b"".join(x.to_bytes(4) for x in H)

if __name__ == "__main__":
    inp = input("What message would you like to hash? ")
    print(f"The hexadecimal representation of the SHA256 hash of \"{inp}\" is {BitArray(sha256(inp.encode())).hex}")
