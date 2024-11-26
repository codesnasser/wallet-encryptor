#!/usr/bin/env python3

"""
Program: Wallet Recovery Phrase Encryptor/Decryptor

Description:
This script provides a secure way to encrypt and decrypt wallet recovery phrases, such as those used for cryptocurrency wallets. It helps users safeguard their sensitive recovery phrases by storing them in an encrypted format and decrypting them only when needed. 

Key Features:
1. **Encryption**: Converts recovery phrases into a secure, encrypted format using a user-provided password.
2. **Decryption**: Recovers the original recovery phrase using the correct password and wallet name.
3. **File Management**: Saves encrypted phrases in a secure folder located in the user's home directory (`~/wallets`).
4. **Error Handling**: Ensures only valid passwords can decrypt the stored recovery phrases.

Usage:
Run the script from the command line with the following arguments:
1. `mode`:
   - `-e`: Encrypt a new recovery phrase.
   - `-d`: Decrypt an existing recovery phrase.
2. `password`: The password to encrypt/decrypt the phrase.
3. `wallet_name`: A unique name identifying the wallet (e.g., `trust_wallet`).

Example Commands:
- To encrypt: `python3 script.py -e mypassword my_wallet`
- To decrypt: `python3 script.py -d mypassword my_wallet`

Dependencies:
- `cryptography` library for secure encryption/decryption.
- `colorama` for styled console output.

Notes:
- Recovery phrases are entered word by word to enhance clarity during input.
- Encrypted files are stored in the `~/wallets` folder with a `.bin` extension.
"""


import argparse
from cryptography.fernet import Fernet
from colorama import Fore, Style
import base64
import hashlib
import os


class RecoveryPhraseEncryptor:
    """
    A class to securely encrypt and decrypt recovery phrases for cryptocurrency wallets.
    """
    
    def __init__(self, password: str):
        """
        Initialize the encryptor with a password.
        """
        self.password = password
        self.key = self._password_to_key(password)

    @staticmethod
    def _password_to_key(password: str) -> bytes:
        """
        Convert a password to a cryptographic key using SHA-256.
        """
        return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt a recovery phrase (plaintext).
        :param plaintext: The recovery phrase to be encrypted.
        :return: Encrypted recovery phrase.
        """
        cipher = Fernet(self.key)
        return cipher.encrypt(plaintext.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypt an encrypted recovery phrase.
        :param ciphertext: The encrypted recovery phrase.
        :return: Decrypted (plaintext) recovery phrase.
        """
        cipher = Fernet(self.key)
        try:
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode()
        except Exception:
            print("Error: Unable to decrypt the content. Please check the password.")
            return ""


def get_folder():
    """
    Get or create a folder to store recovery phrase files.
    """
    secure_folder = os.path.join(os.path.expanduser("~"), "wallets")
    os.makedirs(secure_folder, exist_ok=True)
    return secure_folder


def get_recovery_phrase_input():
    """
    Prompt the user to enter a recovery phrase.
    """
    print("Enter the recovery phrase for your wallet (one word at a time):\n")
    phrase = []
    word_count = 12  # Default word count (can be customized if needed)
    for count in range(1, word_count + 1):
        word = input(f"Word {count}: ")
        phrase.append(f'{count}-{word}')
    return ' '.join(phrase)




def main():
    parser = argparse.ArgumentParser(description="Securely encrypt or decrypt wallet recovery phrases.")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt a new recovery phrase.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt an existing recovery phrase.")
    parser.add_argument("password", help="The password to secure the encryption or decryption process.")
    parser.add_argument("wallet_name", help="The name of the wallet (e.g., trust_wallet).")
    args = parser.parse_args()

    encryptor = RecoveryPhraseEncryptor(password=args.password)

    # Get the secure folder path
    secure_folder = get_folder()
    wallet_encrypted_file = os.path.join(secure_folder, f"{args.wallet_name}.bin")

    if args.encrypt:
        # Encrypt a new recovery phrase
        recovery_phrase = get_recovery_phrase_input()
        encrypted_phrase = encryptor.encrypt(recovery_phrase)

        # Save the encrypted recovery phrase to a file
        with open(wallet_encrypted_file, 'wb') as f:
            f.write(encrypted_phrase)

        print(Fore.GREEN + f"\nThe recovery phrase for the wallet '{args.wallet_name}' has been successfully encrypted." + Style.RESET_ALL)
        print(f"Encrypted file location: {wallet_encrypted_file}")

    elif args.decrypt:
        # Decrypt an existing recovery phrase
        if not os.path.exists(wallet_encrypted_file):
            print(Fore.RED + f"Error: No encrypted recovery phrase file found for the wallet '{args.wallet_name}'." + Style.RESET_ALL)
            return

        with open(wallet_encrypted_file, 'rb') as f:
            encrypted_phrase = f.read()

        decrypted_phrase = encryptor.decrypt(encrypted_phrase)
        if decrypted_phrase:
            for word in decrypted_phrase.split():
                print(Fore.YELLOW + Style.BRIGHT + word + Style.RESET_ALL)
        else:
            print(Fore.RED + "Decryption failed. Please check the password or wallet name." + Style.RESET_ALL)
    else:
        print(Fore.RED + "Error: You must specify either -e (encrypt) or -d (decrypt)." + Style.RESET_ALL)





if __name__ == "__main__":
    main()