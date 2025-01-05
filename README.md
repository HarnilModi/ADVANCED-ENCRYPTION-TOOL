**Name:** HARNIL MODI

**Company:** CODTECH IT SOLUTIONS

**ID:** CT08DAN

**Domain:** Cyber Security & Ethical Hacking

**Duration:** December to January 2025

**Mentor:** Neela Santhosh Kumar

## **Overview of the Project :-** 

### Project:- ADVANCED-ENCRYPTION-TOOL

## Objective
To develop a robust encryption application that allows users to encrypt and decrypt files securely using the AES-256 algorithm, providing a user-friendly interface for seamless operation.

## Key Features
1.File Encryption:

Encrypt files using the AES-256 encryption algorithm.

Ensures data confidentiality by securing file contents.

2.File Decryption:

Decrypt previously encrypted files using the same password.

Restores files to their original form.

3.Password-Based Encryption:

Users set a password to secure their files.

Password-derived encryption keys ensure security.

4.User-Friendly Interface:

Simple GUI built with Tkinter.

Easy file selection and intuitive button-based operations.

5.Error Handling:

Alerts users if decryption fails due to incorrect passwords or corrupted files.

Clear messages guide users in case of issues.

6.Cross-Platform Compatibility:

Works on major operating systems like Windows, macOS, and Linux.

## Technologies Used
Encryption Algorithm: AES-256 (Advanced Encryption Standard, 256-bit key length).

Key Derivation Function: PBKDF2HMAC (Password-Based Key Derivation Function 2 with HMAC).

Padding Scheme: PKCS7 for proper block alignment.

## Programming Language
Python: Chosen for its versatility and rich library support for cryptography and GUI development.

## Libraries
Cryptography:

Provides robust cryptographic primitives.

Used for AES encryption, key generation, and padding.

**Installation:**
- pip install cryptography

2.Tkinter:

Built-in Python library for GUI development.

Used to create a user-friendly interface for file selection and encryption operations.

## How It Works
**1.File Encryption Process:**

-User selects a file via the GUI.

-The user enters a password.

-The tool derives a 256-bit encryption key from the password using the PBKDF2HMAC function.

-The file's contents are padded to align with AES block size (16 bytes).

-AES encryption in CBC mode encrypts the file with the derived key and a randomly generated initialization vector (IV).

-The encrypted file is saved with a .enc extension, including the salt and IV for decryption.

**2.File Decryption Process:**

-User selects an encrypted file via the GUI.

-The user enters the same password used during encryption.

-The tool extracts the salt and IV from the encrypted file.

-A 256-bit decryption key is regenerated using the same password and salt.

-AES decryption in CBC mode decrypts the file's contents.

-Padding is removed to restore the original file.

-The decrypted file is saved with _decrypted appended to its name.

**3.Error Handling:**

-If the user enters the wrong password or selects a corrupted file, the tool displays an error message.

-The GUI guides users with clear instructions for successful operation.

