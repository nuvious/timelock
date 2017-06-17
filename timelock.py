#!/usr/bin/env python

DESCRIPTION = """
Theory:
   Time-lock puzzles and timed-release Crypto (1996)
   by Ronald L. Rivest, Adi Shamir, and David A. Wagner
"""

import os, random, struct
from Crypto.Cipher import AES
from Crypto.Util import number, randpool
from Crypto.Cipher import AES
import sys
import time

# Init PyCrypto RNG
rnd = randpool.RandomPool()

# placeholder variable for packed files
if not 'puzzle' in locals():
    puzzle = None

SECOND = 1
MINUTE = 60
HOUR = MINUTE * 60
DAY = HOUR * 24
MONTH = DAY * 31
YEAR = DAY * 365

MOD_BITS = 2048 # for time-lock puzzle N
AES_BITS = 192

SPEED = -1
SAVE_INTERVAL = -1

def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
				
def calibrate_speed():
    p = number.getPrime(MOD_BITS/2, rnd.get_bytes)
    q = number.getPrime(MOD_BITS/2, rnd.get_bytes)
    N = p*q
    bignum = number.getRandomNumber(MOD_BITS, rnd.get_bytes)
    start = time.time()
    trials = 100
    for i in range(trials):
        bignum = pow(bignum, 2, N)
    return int(trials/(time.time() - start))


def aes_pad(msg):
    return msg + (16 - len(msg) % 16) * '\0'

def aes_encode(msg, key):
    return AES.new(number.long_to_bytes(key)).encrypt(aes_pad(msg))

def aes_decode(ciphertext, key):
    return AES.new(number.long_to_bytes(key)).decrypt(ciphertext)

# Routine adapted from Anti-Emulation-through-TimeLock-puzzles
def makepuzzle(t):
    # Generate 512-bit primes
    p = number.getPrime(MOD_BITS/2, rnd.get_bytes)
    q = number.getPrime(MOD_BITS/2, rnd.get_bytes)
    N = p*q
    totient = (p-1)*(q-1)

    key = number.getRandomInteger(AES_BITS, rnd.get_bytes)
    a = number.getRandomInteger(MOD_BITS, rnd.get_bytes) % N

    e = pow(2, t, totient)
    b = pow(a, e, N)

    cipher_key = (key + b) % N
    return (number.long_to_bytes(key,32), {'N': N, 'a': a, 'steps': t, 'cipher_key': cipher_key})

def eta(remaining, speed):
    seconds = remaining/speed
    if seconds < 100 * SECOND:
        return '%d seconds' % seconds
    elif seconds < 100 * MINUTE:
        return '%d minutes' % (seconds/MINUTE)
    elif seconds < 100 * HOUR:
        return '%d hours' % (seconds/HOUR)
    elif seconds < 60 * DAY:
        return '%d days' % (seconds/DAY)
    elif seconds < 20 * MONTH:
        return '%d months' % (seconds/MONTH)
    else:
        return '%d years' % (seconds/YEAR)

def putestimation(outputstream, puzzle):
    outputstream.write("# Estimated time to solve: %s\n" % eta(puzzle['steps'], SPEED))


def update_speed():
    global SPEED, SAVE_INTERVAL
    if SPEED < 0:
        SPEED = calibrate_speed()
        SAVE_INTERVAL = SPEED * 10 * MINUTE

def save_puzzle(p):
    state = str(p)
    filename = p['ciphertext'] + ".timelock"
    with open(filename, 'w') as f:
        f.write('# Run ./timelock FILENAME > OUTFILE to decode\n')
        putestimation(f, p)
        f.write('\n')
        f.write(state)

def solve_puzzle(p):
    update_speed();
    tmp, N, t = p['a'], p['N'], p['steps']
    start = time.time()
    i = 0
    while i < t:
        if (i+1) % SAVE_INTERVAL == 0:
            p2 = p.copy()
            p2['steps'] = t-i
            p2['a'] = tmp
            save_puzzle(p2)
        tmp = pow(tmp, 2, N)
        if i % 12345 == 1:
            speed = i/(time.time() - start)
            sys.stderr.write('\r%f squares/s, %d remaining, eta %s \r'
                % (speed, t-i, eta(t-i, speed)))
        i += 1
    print >>sys.stderr
    key = (p['cipher_key'] - tmp) % N
    decrypt_file(number.long_to_bytes(key,32), p['ciphertext'], p['ciphertext'] + ".dec")
    os.remove(p['ciphertext'])
    os.rename(p['ciphertext']+".dec",p['ciphertext'])

def _unpack():
    solution = solve_puzzle(puzzle)
    if 'ciphertext' in puzzle:
        print aes_decode(puzzle['ciphertext'], solution)

def _usage():
    if puzzle:
        print """*** This is a self-decoding file ***

If no parameter is given, the embedded puzzle will be decoded.
"""
    print """Usage: ./timelock.py <PARAM>
    --h|help                    display this message
    --new [time]                create a sample puzzle with solution time 'time'
    --encrypt <file> [time]     encode a file using AES with a random key
    --pack <file> [time]        pack a self-decoding file using this script
    --benchmark                 print number of operations per second
    <saved state>               print puzzle solution to stdout"""
    exit(2)

def _new_key_time0(time):
    update_speed()
    try:
        time = int(sys.argv[2]) * SECOND
    except:
        time = 30 * SECOND
    print "Creating test puzzle with difficulty time %d" % time
    (key, puzzle) = makepuzzle(time*SPEED)
    print "key:", key # Recover the key
    save_puzzle(puzzle)

def _encrypt_file_time0(file, time):
    update_speed()
    msg = open(file).read()
    try:
        time = int(sys.argv[3]) * SECOND
    except:
        time = 30 * SECOND
    (key, puzzle) = makepuzzle(time*SPEED)
    print key
    encrypt_file(key,file)
    os.remove(file)
    os.rename(file + ".enc", file)
    puzzle['ciphertext'] = file
    save_puzzle(puzzle)

def _pack_file_time0(self, file, time):
    update_speed()
    msg = open(file).read()
    try:
        time = int(sys.argv[3]) * SECOND
    except:
        time = 30 * SECOND
    (key, puzzle) = makepuzzle(time*SPEED)
    puzzle['ciphertext'] = aes_encode(msg, key)
    print "#!/usr/bin/env python"
    for line in DESCRIPTION.split('\n'):
        print "#", line
    print "# Run this program to recover the original message."
    print "# (scroll down see the program that generated this file)"
    print "#"
    putestimation(sys.stdout, puzzle)
    print "#"
    print
    print "puzzle =", puzzle
    print open(self).read()

def _decode_file(file):
    try:
        puzzle = eval(open(file).read())
    except:
        print "Error parsing saved state."
        exit(1)
    solve_puzzle(puzzle)

class ArgList(list):
    def __init__(self, *args):
        list.__init__(self, *args)
        self.base = self[0]
        self.first = self[1]
        self.second = self[2]
        self.third = self[3]

    def __getitem__(self, i):
        if i >= len(self):
            return None
        return list.__getitem__(self, i)

def main():
    args = ArgList(sys.argv)
    if args.first == '-h' or args.first == '--help':
        _usage()
    elif len(args) == 1 and puzzle:
        _unpack()
    elif len(args) == 1:
        _usage()
    elif args.first == '--new':
        _new_key_time0(args.second)
    elif args.first == '--benchmark':
        update_speed()
        print "%d %d-bit modular exponentiations per second" % (SPEED, MOD_BITS)
    elif args.first == '--encrypt':
        _encrypt_file_time0(args.second, args.third)
    elif args[1] == '--pack':
        _pack_file_time0(args.base, args.second, args.third)
    else:
        _decode_file(args.first)

if __name__ == "__main__":
    main()
