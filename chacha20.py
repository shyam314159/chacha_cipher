mask = 0xffffffff  # mask to put everything in 32 bits


# rotates left by given number of places
def rotl(a, b):
    return ((a << b) & mask) | (a >> (32 - b))


# the  quarter-round function
def qr(encrypt, a, b, c, d):
    a = int(a, 16)
    b = int(b, 16)
    c = int(c, 16)
    d = int(d, 16)
    if encrypt == 'salsa':
        # qr function for salsa20
        b ^= rotl((a + d) & mask, 7)
        c ^= rotl((b + a) & mask, 9)
        d ^= rotl((c + b) & mask, 13)
        a ^= rotl((d + c) & mask, 18)
        return '0x{:0x}'.format(a), '0x{:0x}'.format(b), '0x{:0x}'.format(c), '0x{:0x}'.format(d)

    if encrypt == 'chacha':
        # qr function for chacha
        a += b
        d ^= a
        d = rotl(d & mask, 16)
        c += d
        b ^= c
        b = rotl(b & mask, 12)
        a += b
        d ^= a
        d = rotl(d & mask, 8)
        c += d
        b ^= c
        b = rotl(b & mask, 7)
        return '0x{:0x}'.format(a), '0x{:0x}'.format(b), '0x{:0x}'.format(c), '0x{:0x}'.format(d)


# generates key string for given block counter and other parameters
def key_generator(encrypt, key, block_counter, nonce):
    c = ['0x61707865', '0x3320646e', '0x79622d32', '0x6b206574']

    key = key.encode('utf-8')
    k = ['0x' + key[i:i + 4].hex() for i in range(0, len(key), 4)]
    if len(key) == 16:
        k = k + k

    block_counter = '{:016x}'.format(block_counter)
    b = ['0x' + block_counter[i:i + 8] for i in range(0, len(block_counter), 8)]

    nonce = '{:016x}'.format(nonce)
    n = ['0x' + nonce[i:i + 8] for i in range(0, len(nonce), 8)]
    if encrypt == 'salsa':
        s = [c[0], k[0], k[1], k[2],
             k[3], c[1], n[0], n[1],
             b[0], b[1], c[2], k[4],
             k[5], k[6], k[7], c[3]]
        # storing s in other variable to xor after 20 rounds
        s1 = [c[0], k[0], k[1], k[2],
              k[3], c[1], n[0], n[1],
              b[0], b[1], c[2], k[4],
              k[5], k[6], k[7], c[3]]
        for i in range(10):
            # for odd round
            s[0], s[4], s[8], s[12] = qr('salsa', s[0], s[4], s[8], s[12])
            s[5], s[9], s[13], s[1] = qr('salsa', s[5], s[9], s[13], s[1])
            s[10], s[14], s[2], s[6] = qr('salsa', s[10], s[14], s[2], s[6])
            s[15], s[3], s[7], s[11] = qr('salsa', s[15], s[3], s[7], s[11])

            # for even round
            s[0], s[1], s[2], s[3] = qr('salsa', s[0], s[1], s[2], s[3])
            s[5], s[6], s[7], s[4] = qr('salsa', s[5], s[6], s[7], s[4])
            s[10], s[11], s[8], s[9] = qr('salsa', s[10], s[11], s[8], s[9])
            s[15], s[12], s[13], s[14] = qr('salsa', s[15], s[12], s[13], s[14])
        s = [int(a, 16) ^ int(b, 16) for a, b in zip(s, s1)]
        s = ['0x{:0x}'.format(i) for i in s]
        a = ''.join(''.join(s).split('0x'))
        b = ''.join([chr(int(''.join(c), 16)) for c in zip(a[0::2], a[1::2])])
        return [ord(i) for i in b]

    if encrypt == 'chacha':
        s = [c[0], c[1], c[2], c[3],
             k[0], k[1], k[2], k[3],
             k[4], k[5], k[6], k[7],
             b[0], b[1], n[0], n[1]]
        # storing s in other variable to xor after 20 rounds
        s1 = [c[0], k[0], k[1], k[2],
              k[3], c[1], n[0], n[1],
              b[0], b[1], c[2], k[4],
              k[5], k[6], k[7], c[3]]
        for i in range(10):
            # for odd round
            s[0], s[4], s[8], s[12] = qr('chacha', s[0], s[4], s[8], s[12])
            s[1], s[5], s[9], s[13] = qr('chacha', s[1], s[5], s[9], s[13])
            s[2], s[6], s[10], s[14] = qr('chacha', s[2], s[6], s[10], s[14])
            s[3], s[7], s[11], s[15] = qr('chacha', s[3], s[7], s[11], s[15])

            # for even round
            s[0], s[5], s[10], s[15] = qr('chacha', s[0], s[5], s[10], s[15])
            s[1], s[6], s[11], s[12] = qr('chacha', s[1], s[6], s[11], s[12])
            s[2], s[7], s[8], s[13] = qr('chacha', s[2], s[7], s[8], s[13])
            s[3], s[4], s[9], s[14] = qr('chacha', s[3], s[4], s[9], s[14])
        s = [int(a, 16) ^ int(b, 16) for a, b in zip(s, s1)]
        s = ['0x{:0x}'.format(i) for i in s]
        a = ''.join(''.join(s).split('0x'))
        b = ''.join([chr(int(''.join(c), 16)) for c in zip(a[0::2], a[1::2])])
        return [ord(i) for i in b]


def salsa(message, key, block_counter=0, nonce=0):
    cunks = [message[i:i + len(key)] for i in range(0, len(message), len(key))]
    cipher = ''
    for i in cunks:
        effective_key = key_generator('salsa', key, block_counter, nonce)
        a = [CHR for CHR in i]
        for m in range(len(a)):
            cipher += chr(ord(a[m]) ^ effective_key[m])

        # increments block counter for each chunk
        block_counter += 1
    return cipher


def chacha(message, key, block_counter=0, nonce=0):
    cunks = [message[i:i + len(key)] for i in range(0, len(message), len(key))]
    cipher = ''
    for i in cunks:
        effective_key = key_generator('salsa', key, block_counter, nonce)
        a = [CHR for CHR in i]
        for m in range(len(a)):
            cipher += chr(ord(a[m]) ^ effective_key[m])

        # increments block counter for each chunk
        block_counter += 1
    return cipher


if __name__ == '__main__':
    key = 'jua#vH2(natD<Se3'
    a = salsa('i made it i can\'t believe it i actually did build chacha and salsa cypher more cipher algorithms ahead', key, 392, 623)
    a = salsa(a, key, 392, 623)

    b = chacha('i made it i can\'t believe it i actually did build chacha and salsa cypher more cipher algorithms ahead', key, 392, 623)
    b = chacha(b, key, 392, 623)
    print(a)
    print(b)
