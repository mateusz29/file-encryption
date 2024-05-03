from tkinter import Tk, Button, filedialog, messagebox, Text, Frame, Scrollbar
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

selected_mode = None
mode_buttons = {}

def encrypt_file(file_path, key, mode):
    """
    Function to encrypt a file in the selected mode.
    """
    try:
        # Creating an instance of AES.Cipher object with the key
        if mode == "ECB":
            chosen_mode = AES.MODE_ECB
        elif mode == "CBC":
            chosen_mode = AES.MODE_CBC
        elif mode == "CTR":
            chosen_mode = AES.MODE_CTR
        elif mode == "OFB":
            chosen_mode = AES.MODE_OFB

        cipher = AES.new(key, chosen_mode)

        with open(file_path, 'rb') as file:
            plaintext = file.read()

            # Displaying the file if the file is smaller than 400MB
            if os.path.getsize(file_path) < 1024*1024*400:
                utf8_text = plaintext.decode('utf-8', errors='replace')
                text_display1.configure(state="normal")
                text_display1.delete("1.0", "end")
                text_display1.insert("end", utf8_text)
                text_display1.configure(state="disabled")
            else:
                messagebox.showinfo("Warning", "The file is too big, it will be encrypted, but not shown.")

            # Encrypting the plaintext
            if mode == "CBC" or mode == "ECB":
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            elif mode == "CTR" or mode == "OFB":
                ciphertext = cipher.encrypt(plaintext)

        # Saving the encrypted file
        with open(file_path + mode + '.enc', 'wb') as file:
            if mode == "ECB":
                file.write(ciphertext)
            elif mode == "CBC" or mode == "OFB":
                file.write(cipher.iv + ciphertext)
            elif mode == "CTR":
                file.write(cipher.nonce + ciphertext)

    except Exception as e:
        messagebox.showinfo("Warning", "An error occurred while encrypting the file:\n" + str(e))

def decrypt_file(file_path, key, mode):
    """
    Function to decrypt a file in the selected mode.
    """
    try:
        if os.path.getsize(file_path) >= 1024*1024*400:
            messagebox.showinfo("Warning", "The file is too big, it will be decrypted, but not shown.")

        with open(file_path, 'rb') as file:
            # Decrypting the encrypted text
            if mode == "ECB":
                ciphertext = file.read()
                # Creating an instance of AES.Cipher object with the key
                cipher = AES.new(key, AES.MODE_ECB)
                # Decrypting the encrypted text
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode == "CBC":
                # Reading the initialization vector from the file
                iv = file.read(AES.block_size)
                file.seek(AES.block_size)
                ciphertext = file.read()
                # Creating an instance of AES.Cipher object with the key
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                # Decrypting the encrypted text
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode == "CTR":
                # Reading the nonce from the file
                nonce = file.read(AES.block_size//2)
                file.seek(AES.block_size//2)
                ciphertext = file.read()
                # Creating an instance of AES.Cipher object with the key
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                # Decrypting the encrypted text
                plaintext = cipher.decrypt(ciphertext)
            elif mode == "OFB":
                # Reading the initialization vector from the file
                iv = file.read(AES.block_size)
                file.seek(AES.block_size)
                ciphertext = file.read()
                # Creating an instance of AES.Cipher object with the key
                cipher = AES.new(key, AES.MODE_OFB, iv=iv)
                # Decrypting the encrypted text
                plaintext = cipher.decrypt(ciphertext)

        # Saving the decrypted file
        with open(file_path[:-11] + "decrypted" + file_path[-11:-7], 'wb') as file:
            file.write(plaintext)
            # Displaying the decrypted text if the file is smaller than 400MB
            if os.path.getsize(file_path) < 1024*1024*400:
                utf8_text = plaintext.decode('utf-8', errors='replace')
                text_display2.configure(state="normal")
                text_display2.delete("1.0", "end")
                text_display2.insert("end", utf8_text)
                text_display2.configure(state="disabled")

    except Exception as e:
        messagebox.showerror("Error", "An error occurred while decrypting the file:\n" + str(e))

def encrypt_button_click():
    """
    Function to handle the click event of the encryption button.
    """
    if selected_mode is None:
        messagebox.showerror("Error", "Choose encryption mode.")
    else:
        file_path = filedialog.askopenfilename(title="Choose file to encrypt")
        if file_path:
            key = get_random_bytes(16)  # Generating a random key
            mode = selected_mode
            encrypt_file(file_path, key, mode)  # Encrypting in the selected mode

            # Saving the key to a file
            key_file_path = file_path + selected_mode + '.key'
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)

def decrypt_button_click():
    """
    Function to handle the click event of the decryption button.
    """
    if selected_mode is None:
        messagebox.showerror("Error", "Choose decryption mode.")
    else:
        file_path = filedialog.askopenfilename(title="Choose file to decrypt")
        if file_path:
            key_file_path = filedialog.askopenfilename(title="Choose key for decrytpion")
            if key_file_path:
                with open(key_file_path, 'rb') as key_file:
                    key = key_file.read()
                    decrypt_file(file_path, key, selected_mode) # Decrypting in the selected mode

def mode_button_click(mode):
    """
    Function to handle the click event of the mode selection button.
    """
    global selected_mode
    selected_mode = mode

    for button in mode_buttons.values():
        if button["text"] == mode:
            button.config(relief="sunken") # Set the relief of the selected mode button to "sunken"
        else:
            button.config(relief="raised") # Set the relief of the other mode buttons to "raised"

def load_text1_file():
    """
    Function to load the content of the first text file.
    """
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, "rb") as file:
            text = file.read()
            utf8_text = text.decode('utf-8', errors='replace')
            text_display1.configure(state="normal")
            text_display1.delete("1.0", "end")
            text_display1.insert("end", utf8_text)
            text_display1.configure(state="disabled")

def load_text2_file():
    """
    Function to load the content of the second text file.
    """
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, "rb") as file:
            text = file.read()
            utf8_text = text.decode('utf-8', errors='replace')
            text_display2.configure(state="normal")
            text_display2.delete("1.0", "end")
            text_display2.insert("end", utf8_text)
            text_display2.configure(state="disabled")

def highlight_differences():
    """
    Function to highlight the differences between the contents of the two text files.
    """
    text1 = text_display1.get("1.0", "end")
    text2 = text_display2.get("1.0", "end")
    text_display2.configure(state="normal")

    text_display2.tag_remove('highlight1', "1.0", "end")
    text_display2.tag_remove('highlight2', "1.0", "end")

    line_num, char_num, char_num_in_line = 1, 0, 0
    for char in text2:
        if char_num < len(text1):
            if char != text1[char_num]:
                text_display2.tag_add('highlight1', f'{line_num}.{char_num_in_line}', f'{line_num}.{char_num_in_line+1}')
            else:
                text_display2.tag_add('highlight2', f'{line_num}.{char_num_in_line}', f'{line_num}.{char_num_in_line+1}')
        else:
            # If the 2nd file is longer than the 1st file the additional characters will be all highlighted in red
            text_display2.tag_add('highlight1', f'{line_num}.{char_num_in_line}', f'{line_num}.{char_num_in_line+1}')

        if char == '\n':
            # If a character is an end of line, reset the num of characters in a line and increment the num of lines
            line_num += 1
            char_num_in_line = -1
        char_num += 1
        char_num_in_line += 1

    text_display2.configure(state="disabled")

if __name__ == '__main__':
    # Creating the main application window
    window = Tk()
    window.title("Encryption and decryption of files")
    window.geometry("700x680")
    window.resizable(False, False)

    # A frame for all the buttons
    buttons_frame = Frame(window)
    buttons_frame.pack(side="right", padx=50)

    modes = ["ECB", "CBC", "CTR", "OFB"]
    for mode in modes:
        mode_button = Button(buttons_frame, text=mode, relief="raised", command=lambda m=mode: mode_button_click(m), height=1, width=10)
        mode_button.pack()
        mode_buttons[mode] = mode_button

    encrypt_button = Button(buttons_frame, text="Encrypt file", command=encrypt_button_click, height=1, width=10)
    encrypt_button.pack()

    decrypt_button = Button(buttons_frame, text="Decrypt file", command=decrypt_button_click, height=1, width=10)
    decrypt_button.pack()

    load_button1 = Button(buttons_frame, text="Load 1 file", command=load_text1_file, height=1, width=10)
    load_button1.pack()

    load_button2 = Button(buttons_frame, text="Load 2 file", command=load_text2_file, height=1, width=10)
    load_button2.pack()

    compare_button = Button(buttons_frame, text="Compare", command=highlight_differences, height=1, width=10)
    compare_button.pack()

    display_frame1 = Frame(window)
    display_frame1.pack(pady=10)

    display_frame2 = Frame(window)
    display_frame2.pack()

    text_display1 = Text(display_frame1, height=20, width=60, state="disabled")
    text_display2 = Text(display_frame2, height=20, width=60, state="disabled")

    scrollbar_y = Scrollbar(display_frame1, orient="vertical", command=text_display1.yview)
    scrollbar_y.pack(side="right", fill="y")

    scrollbar_y2 = Scrollbar(display_frame2, orient="vertical", command=text_display2.yview)
    scrollbar_y2.pack(side="right", fill="y")

    text_display1.configure(yscrollcommand=scrollbar_y.set)
    text_display1.pack()

    text_display2.configure(yscrollcommand=scrollbar_y2.set)
    text_display2.pack()

    text_display2.tag_configure("highlight1", background="lightcoral")
    text_display2.tag_configure("highlight2", background="lightgreen")

    window.mainloop()