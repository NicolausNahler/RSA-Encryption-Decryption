import argparse
import random
import secrets


def primes():
    yield from primes.prime_nums

    num = primes.prime_nums[-1] + 2
    while True:
        if is_prime(num):
            primes.prime_nums.append(num)
            yield num
        num += 2


primes.prime_nums = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
                     101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
                     199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
                     317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
                     443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541]


def is_prime(num):
    """
    checks if a number is a prime number, with the help of the is_prim_miller_rabin method
    :param num: the to be checked number
    :return: boolean
    """
    if num in primes.prime_nums:
        return True

    for prime_num in primes.prime_nums:
        if num % prime_num == 0:
            return False
    return is_prim_miller_rabin(num)


def is_prim_miller_rabin(n, k=20):
    """
    checks if a number is a prime number, with the is_prim_miller_rabin method
    :param n: the to be checked number
    :param k: how long th number is checked with the is_prim_miller_rabin method
    :return: boolean
    """
    d, s = 0, n - 1
    while s % 2 == 0:
        d += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(d - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=500):
    """
    generates a random number with a number of bits
    :param bits: the number of bits
    :return: a key
    """
    key = ((1 << bits - 1) | 1) | secrets.SystemRandom().getrandbits(bits)
    while not is_prime(key):
        key += 2
    return key


def generate_keys(number_of_bits):
    """
    generates keys for rsa, with a number of bits
    :param number_of_bits: the number of bits
    :return: private and public key
    >>> ((e, n, _), (d, _, _)) = generate_keys(512)
    >>> for x in [8, 23876685, 673426754327521, 623485257625452, 2554275725752]:
    ...     c = pow(x,e,n)
    ...     y = pow(c,d,n)
    ...     assert x == y
    """
    p = generate_prime(number_of_bits // 2 + 1)
    q = generate_prime(number_of_bits // 2 + 1)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return (e, n, number_of_bits), (d, n, number_of_bits)


def write_keys(number_of_bits, key_path):
    """
    writes both private and public keys into the key_private.txt and the key_public.txt file
    :param number_of_bits: the number of bits the keys will have
    :return: both files will have the keys written into them
    """
    ((e, n, key_length), (d, _, _)) = generate_keys(number_of_bits)
    with open(f'{key_path}/key_private.txt', 'w') as file:
        print(e, n, key_length, file=file, sep='\n')
    with open(f'{key_path}/key_public.txt', 'w') as file:
        print(d, n, key_length, file=file, sep='\n')


def read_public_key(path):
    """
    reads the public key
    :param path: the path where the public key is stored
    :return: the public key
    """
    with open(path + "/key_public.txt", "r") as file:
        d = int(file.readline())
        n = int(file.readline())
        number_of_bits = int(file.readline())
    return d, n, number_of_bits


def read_private_key(path):
    """
    reads the private key
    :param path: the path where the private key is stored
    :return: the private key
    """
    with open(path + "/key_private.txt", "r") as file:
        e = int(file.readline())
        n = int(file.readline())
        number_of_bits = int(file.readline())
    return e, n, number_of_bits


def file2ints(path, blocksize):
    """
    reads a file and yields parts or blocks of that file
    :param path: the path of the file
    :param blocksize: the size of the part or block
    :return: generator object
    """
    with open(path, 'rb') as file:
        while data := file.read(blocksize // 8):
            yield int.from_bytes(data, byteorder='little')


def ints2file(path, blocksize):
    """
    reads a file and yields parts or blocks of that file
    :param path: the path of the file
    :param blocksize: the size of the part or block
    :return: generator object
    """
    with open(path, 'rb') as file:
        while data := file.read(blocksize // 8 + 1):
            yield int.from_bytes(data, byteorder='little')


def encrypt_file(input_path, key_path, output_path):
    """
    encrypts a file into another file (using a key)
    :param input_path: the path of the input file
    :param key_path: the path of the key
    :param output_path: the path of the output file
    :return: a new encrypted file
    """
    (e, n, blocksize) = read_private_key(key_path)
    with open(output_path, 'wb') as file:
        for m in file2ints(input_path, blocksize):
            file.write(pow(m, e, n).to_bytes(blocksize // 8 + 1, byteorder='little'))


def decrypt_file(input_path, key_path, output_path):
    """
    decrypts a file into another file (using a key)
    :param input_path: the path of the input file
    :param key_path: the path of the key
    :param output_path: the path of the output file
    :return: a new decrypted file
    """
    (d, n, blocksize) = read_public_key(key_path)
    with open(output_path, 'wb') as file:
        for m in ints2file(input_path, blocksize):
            file.write(pow(m, d, n).to_bytes(blocksize // 8, byteorder='little'))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbosity", help="increase output verbosity", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-k", "--keygen", nargs='+', help="generate new keys with the given length")
    group.add_argument("-e", "--encrypt", nargs='+', dest="encrypt_filepath", help="encrypt file")
    group.add_argument("-d", "--decrypt", nargs='+', dest="decrypt_filepath", help="decrypt file")
    args = parser.parse_args()
    print(args)

    if args.keygen:
        if len(args.keygen) == 1:
            args.keygen.append('./keys')
        if args.verbosity:
            print("Key size: ", args.keygen[0])
            print(f'Private key path: {args.keygen[1]}/key_private.txt')
            print(f'Public key path: {args.keygen[1]}/key_public.txt')
            print("Success!")
        write_keys(int(args.keygen[0]), args.keygen[1])
    if args.encrypt_filepath:
        if len(args.encrypt_filepath) == 1:
            args.encrypt_filepath.append(args.encrypt_filepath[0] + '.encrypted')
        if len(args.encrypt_filepath) == 2:
            args.encrypt_filepath.append('./keys')
        if args.verbosity:
            print("Input file path: ", args.encrypt_filepath[0])
            print("Output file path: ", args.encrypt_filepath[1])
            print(f'Private key path: {args.encrypt_filepath[2]}/key_private.txt')
            print(f'Public key path: {args.encrypt_filepath[2]}/key_public.txt')
            print("Success!")
        encrypt_file(args.encrypt_filepath[0], args.encrypt_filepath[2], args.encrypt_filepath[1])
    if args.decrypt_filepath:
        if len(args.decrypt_filepath) == 1:
            args.decrypt_filepath.append(args.decrypt_filepath[0][:-10] + '.decrypted')
        if len(args.decrypt_filepath) == 2:
            args.decrypt_filepath.append('./keys')
        if args.verbosity:
            print("Input file path: ", args.decrypt_filepath[0])
            print("Output file path: ", args.decrypt_filepath[1])
            print(f'Private key path: {args.decrypt_filepath[2]}/key_private.txt')
            print(f'Public key path: {args.decrypt_filepath[2]}/key_public.txt')
            print("Success!")
        decrypt_file(args.decrypt_filepath[0], args.decrypt_filepath[2], args.decrypt_filepath[1])
