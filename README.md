# File Encryption using Symmetric Block Ciphers

This project is a file encryption and decryption tool developed as a part of the "Introduction to Cybersecurity" university course. It offers a graphical user interface for encrypting and decrypting files using symmetric block ciphers. The supported modes include ECB (Electronic Codebook), CBC (Cipher Block Chaining), CTR (Counter), and OFB (Output Feedback).

## Features

- **Symmetric Block Ciphers:** Utilizes AES (Advanced Encryption Standard) symmetric block cipher for encryption and decryption.
- **Multiple Modes:** Offers four different encryption modes: ECB, CBC, CTR, and OFB, each with its own characteristics and advantages.
- **File Comparison:** Allows users to compare the encrypted and decrypted files to check for any differences.
- **Graphical User Interface:** Provides a user-friendly interface for easy interaction.

## How to Use

1. **Select Encryption Mode:** Choose one of the encryption modes (ECB, CBC, CTR, OFB) by clicking on the respective button.
2. **Encrypt File:** Click on the "Encrypt file" button to select a file for encryption. The encrypted file will be saved with the selected encryption mode's extension.
3. **Decrypt File:** Click on the "Decrypt file" button to select an encrypted file and its corresponding key file for decryption. The decrypted file will be saved with the "decrypted" suffix.
4. **Compare Files:** After loading two files using the "Load 1 file" and "Load 2 file" buttons, click on "Compare" to highlight any differences between them.

## Requirements

- Python 3.x
- tkinter library
- pycryptodome library
