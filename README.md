# Hashing Utility

This Python script provides a utility for hashing strings using various hashing algorithms, including MD5, SHA-1, SHA-512, and bcrypt. It also allows verifying a password hash using bcrypt.

## Functions

### `md5_hash(string)`

This function takes a string as input and computes its MD5 hash. It returns the hexadecimal representation of the hash.

### `sha1_hash(string)`

This function takes a string as input and computes its SHA-1 hash. It returns the hexadecimal representation of the hash.

### `sha512_hash(string)`

This function takes a string as input and computes its SHA-512 hash. It returns the hexadecimal representation of the hash.

### `bcrypt_hash(string)`

This function takes a string as input and computes its bcrypt hash with a randomly generated salt. It returns the hashed password as bytes.

### `menu()`

This function displays a menu for selecting the hashing algorithm or verifying a password using bcrypt. It returns the user's choice as an integer.

### `main()`

The main function provides a command-line interface to interact with the hashing utility. It repeatedly displays the menu, takes user input, and performs the selected hashing operation or password verification.

## Usage

1. Run the script using Python:
python script_name.py

2. Choose the desired hashing algorithm or password verification option from the menu.

3. Enter the string you want to hash or the password for verification when prompted.

4. The script will display the hashed value or the result of password verification.

## Note

- This code provides a basic utility for hashing and verifying passwords. For production use, consider more robust password management libraries.

- Ensure you have the required Python libraries (`hashlib` and `bcrypt`) installed.

- Make sure to customize and expand this code as needed for your specific use case.

- Use bcrypt for securely hashing and verifying passwords, as it is designed for password storage and offers protection against common attacks.

