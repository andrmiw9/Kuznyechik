# non-lin table
pi = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5,
    132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235,
    52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
    112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161,
    150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117,
    25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245,
    36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15,
    236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
    96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
    146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64,
    134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73,
    76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164,
    45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230,
    244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
]

# non-lin table reversed
pi_rev = [0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
          0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
          0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
          0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
          0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
          0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
          0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
          0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
          0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
          0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
          0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
          0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
          0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
          0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
          0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
          0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
          0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
          0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
          0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
          0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
          0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
          0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
          0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
          0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
          0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
          0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
          0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
          0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
          0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
          0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
          0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
          0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74]


# utility ------------------------------------------------------------------

# x and y >= 0
# Their associated binary polynomials are multiplied.
# The associated integer to this product is returned.
def multiply_ints_as_polynomials(x, y):
    if x == 0 or y == 0:
        return 0
    z = 0
    while x != 0:
        if x & 1 == 1:
            z ^= y
        y <<= 1
        x >>= 1
    return z


# Returns the number of bits that are used
# to store the positive integer x.
def number_bits(x):
    nb = 0
    while x != 0:
        nb += 1
        x >>= 1
    return nb


# x must be >=0 int
# m must be >0 int
def mod_int_as_polynomial(x, m):
    nbm = number_bits(m)
    while True:
        nbx = number_bits(x)
        if nbx < nbm:
            return x
        mshift = m << (nbx - nbm)
        x ^= mshift


# x,y (input) 8
# output 8
def kuznyechik_multiplication(x, y):
    z = multiply_ints_as_polynomials(x, y)
    m = int('111000011', 2)
    return mod_int_as_polynomial(z, m)


# # x is 128 bits (vector of 16 bytes)
# # return value is 8-bits
def kuznyechik_linear_functional(x):
    C = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]  # koeffs or ryad
    y = 0
    while x != 0:
        y ^= kuznyechik_multiplication(x & 0xff, C.pop())
        x >>= 8
    return y


# transforms base ---------------------------------------------------------------

# non-lin
def S(x):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y ^= pi[(x >> (8 * i)) & 0xff]
    return y


# non-lin inverse
def S_inv(x):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y ^= pi_rev[(x >> (8 * i)) & 0xff]
    return y


# 128 in, 128 out
def R(x):
    a = kuznyechik_linear_functional(x)
    return (a << 8 * 15) ^ (x >> 8)


# 128 in, 128 out
def R_inv(x):
    a = x >> 15 * 8
    x = (x << 8) & (2 ** 128 - 1)
    b = kuznyechik_linear_functional(x ^ a)
    return x ^ b


# lin, 128 in, 128 out
def L(x):
    for _ in range(16):
        x = R(x)
    return x


# lin inverse, 128 in, 128 out
def L_inv(x):
    for _ in range(16):
        x = R_inv(x)
    return x


# calc c
# def gen_C():
#     iter_num = [[0] * 16 for i in range(32)]
#     for i in range(32):  # 32 c
#         for j in range(16):  # block size
#             iter_num[i][j] = 0
#         iter_num[i][15] = i + 1
#     for i in range(32):
#         const_c[i] = L(iter_num[i])

# Main part -----------------------------------------------------------------------

# key 256 bit
# gen 10 keys, 128 bit each
def gen_iter_keys(k):
    keys = []
    a = k >> 128
    b = k & (2 ** 128 - 1)
    keys.append(a)  # first 2 keys from basic key
    keys.append(b)  #

    # gen 10 iter keys
    for i in range(4):
        for j in range(8):  # 8 iterations of Feistels network
            c = L(8 * i + j + 1)  # calc C v2 (L ot nomera iterazii)
            # print('iter c:', hex(c))
            (a, b) = (L(S(a ^ c)) ^ b, a)
        keys.append(a)
        keys.append(b)
    print('iterations keys in hex form:', [hex(x) for x in keys])
    return keys


# x (text to cipher) 128
# key is 256
def kuznyechik_encrypt(x, k):
    keys = gen_iter_keys(k)
    for round in range(9):  # 9 rounds
        x = x ^ keys[round]  # xor with iterations key
        x = S(x)  # non-lin
        x = L(x)  # lin
        # x = L(S(x ^ keys[round]))
    return x ^ keys[-1]  # xor


# encoded text x is 128 bit
# key is 256
def kuznyechik_decrypt(x, k):
    keys = gen_iter_keys(k)
    keys.reverse()
    for round in range(9):  # 9 rounds
        x = S_inv(L_inv(x ^ keys[round]))  # same, but using inversing
    return x ^ keys[-1]  # xor


if __name__ == '__main__':
    s = "Mashkin nash <34"
    text_tocipher_int16 = int("".join("{:02x}".format(ord(c)) for c in s), 16)

    # key = int('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef',
    # 16)  # 128 bit key in 16x systeme schislenya
    key = int('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef', 16)

    print('start text:', s)
    print('start text in int form:', text_tocipher_int16)

    encoded = kuznyechik_encrypt(text_tocipher_int16, key)

    print('encoded:', encoded)
    print('encoded hex:', hex(encoded))

    decoded = kuznyechik_decrypt(encoded, key)

    print('decoded:', decoded)
    print('decoded hex:', hex(decoded))

    decoded = hex(decoded)[2:]
    print('decoded after hex:', decoded)

    outp = [chr(int(decoded[i:i + 2], 16)) for i in range(0, 32, 2)]
    # outp = [decoded[i:i + 2] for i in range(0, 32, 2)]
    print(*outp)

    # test1.5
    print('test 1.5')
    print('start plain text = 1122334455667700ffeeddccbbaa9988')
    test1_5 = int("1122334455667700ffeeddccbbaa9988", 16)
    print('start plaint text after int 16x:', test1_5)

    enc = kuznyechik_encrypt(test1_5, key)
    dec = kuznyechik_decrypt(enc, key)

    print('decoded:', dec)
    dec = hex(dec)[2:]
    print('decoded after hex', dec)
    # print('decoded hex:', hex(decoded))

    # test

    pass
