from hashlib import *
import bcrypt


def md5_hash(string):
    hash_method = md5()
    string_bytes = string.encode('utf-8')
    hash_method.update(string_bytes)
    string_hashed = hash_method.hexdigest()
    return string_hashed


def sha1_hash(string):
    hash_method = sha1()
    string_bytes = string.encode('utf-8')
    hash_method.update(string_bytes)
    string_hashed = hash_method.hexdigest()
    return string_hashed


def sha512_hash(string):
    hash_method = sha512()
    string_bytes = string.encode('utf-8')
    hash_method.update(string_bytes)
    string_hashed = hash_method.hexdigest()
    return string_hashed


def bcrypt_hash(string):
    salt = bcrypt.gensalt()
    string_bytes = string.encode('utf-8')
    string_hashed = bcrypt.hashpw(string_bytes, salt)
    return string_hashed


def menu():
    print("""\nwhich hashing algorithm you prefer : \n
    /1/ hashing with MD5
    /2/ hashing with SHA1 
    /8/ hashing with SHA512
    /9/ hashing with bcrypt
    /10/ verify a password with bcrypt
        
    /0/ exit\n""")
    choice = int(input("Enter your choice here : "))
    while choice not in [0, 1, 2, 8, 9, 10]:
        print("\nYour choice is invalid !")
        choice = int(input("Enter your choice here : "))
    return choice


def main():
    while True:
        choice = menu()
        if choice == 0:
            break
        else:
            string_to_hash = str(input("\nEnter your message to hash :"))
            if choice == 1:
                print(f'Your message hashed is : {md5_hash(string_to_hash)}')
            elif choice == 2:
                print(f'Your message hashed is : {sha1_hash(string_to_hash)}')
            elif choice == 8:
                print(f'Your message hashed is : {sha512_hash(string_to_hash)}')
            elif choice == 9:
                print(f'Your message hashed is : {bcrypt_hash(string_to_hash).decode()}')
            elif choice == 10:
                password_old = input("Entre your password :")
                result = bcrypt.checkpw(password_old.encode('utf-8'), string_to_hash.encode('utf-8'))
                print(f'the password is a {result} match')


main()
