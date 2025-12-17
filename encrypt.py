"""
PNG Steganography Tool
Hide encrypted files inside PNG images using LSB steganography

This tool is open source - feel free to contribute!
Main features to potentially add:
- Support for different image formats (though PNG is best for lossless storage)
- Batch processing multiple files
- Compression before encryption to fit larger files
- Progress bars for large file operations
- Image quality comparison metrics
"""

import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
import secrets
import threading


class StegoApp:
    """
    Main application class for the GUI
    
    For developers: The UI is intentionally simple with just two modes.
    If you want to add features like batch processing or advanced options,
    consider adding a settings menu or preferences dialog rather than
    cluttering the main interface.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("PNG Steganography Tool")
        self.root.geometry("600x500")
        self.root.configure(bg="#1e1e1e")
        
        # Colors for dark theme
        self.bg = "#1e1e1e"
        self.fg = "#ffffff"
        self.btn_bg = "#2d2d2d"
        self.btn_active = "#3d3d3d"
        self.entry_bg = "#2d2d2d"
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="PNG Steganography Tool",
            font=("Arial", 18, "bold"),
            bg=self.bg,
            fg="#4CAF50"
        )
        title.pack(pady=20)
        
        # Mode selection
        mode_frame = tk.Frame(self.root, bg=self.bg)
        mode_frame.pack(pady=10)
        
        self.mode = tk.StringVar(value="encrypt")
        
        tk.Radiobutton(
            mode_frame,
            text="Encrypt File",
            variable=self.mode,
            value="encrypt",
            command=self.switch_mode,
            bg=self.bg,
            fg=self.fg,
            selectcolor=self.btn_bg,
            activebackground=self.bg,
            activeforeground=self.fg,
            font=("Arial", 11)
        ).pack(side='left', padx=20)
        
        tk.Radiobutton(
            mode_frame,
            text="Decrypt File",
            variable=self.mode,
            value="decrypt",
            command=self.switch_mode,
            bg=self.bg,
            fg=self.fg,
            selectcolor=self.btn_bg,
            activebackground=self.bg,
            activeforeground=self.fg,
            font=("Arial", 11)
        ).pack(side='left', padx=20)
        
        # Main content frame
        self.content_frame = tk.Frame(self.root, bg=self.bg)
        self.content_frame.pack(fill='both', expand=True, padx=30, pady=20)
        
        self.show_encrypt_ui()
        
    def switch_mode(self):
        # Clear current content
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Show appropriate UI based on mode
        if self.mode.get() == "encrypt":
            self.show_encrypt_ui()
        else:
            self.show_decrypt_ui()
    
    def show_encrypt_ui(self):
        # File to hide
        tk.Label(self.content_frame, text="File to Hide:", bg=self.bg, fg=self.fg, 
                font=("Arial", 10)).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        file_frame = tk.Frame(self.content_frame, bg=self.bg)
        file_frame.grid(row=1, column=0, sticky='ew', pady=(0, 15))
        
        self.encrypt_file_entry = tk.Entry(file_frame, bg=self.entry_bg, fg=self.fg, 
                                           font=("Arial", 10), insertbackground=self.fg)
        self.encrypt_file_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(file_frame, text="Browse", command=self.browse_encrypt_file,
                 bg=self.btn_bg, fg=self.fg, activebackground=self.btn_active,
                 font=("Arial", 9)).pack(side='left', padx=(5, 0))
        
        # Cover image
        tk.Label(self.content_frame, text="Cover Image (PNG):", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        image_frame = tk.Frame(self.content_frame, bg=self.bg)
        image_frame.grid(row=3, column=0, sticky='ew', pady=(0, 15))
        
        self.encrypt_image_entry = tk.Entry(image_frame, bg=self.entry_bg, fg=self.fg,
                                            font=("Arial", 10), insertbackground=self.fg)
        self.encrypt_image_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(image_frame, text="Browse", command=self.browse_encrypt_image,
                 bg=self.btn_bg, fg=self.fg, activebackground=self.btn_active,
                 font=("Arial", 9)).pack(side='left', padx=(5, 0))
        
        # Output location
        tk.Label(self.content_frame, text="Save As:", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=4, column=0, sticky='w', pady=(0, 5))
        
        output_frame = tk.Frame(self.content_frame, bg=self.bg)
        output_frame.grid(row=5, column=0, sticky='ew', pady=(0, 15))
        
        self.encrypt_output_entry = tk.Entry(output_frame, bg=self.entry_bg, fg=self.fg,
                                             font=("Arial", 10), insertbackground=self.fg)
        self.encrypt_output_entry.insert(0, "output_stego.png")
        self.encrypt_output_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(output_frame, text="Browse", command=self.browse_encrypt_output,
                 bg=self.btn_bg, fg=self.fg, activebackground=self.btn_active,
                 font=("Arial", 9)).pack(side='left', padx=(5, 0))
        
        # Password
        tk.Label(self.content_frame, text="Password:", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=6, column=0, sticky='w', pady=(0, 5))
        
        self.encrypt_password_entry = tk.Entry(self.content_frame, show="*", bg=self.entry_bg, 
                                               fg=self.fg, font=("Arial", 10), 
                                               insertbackground=self.fg)
        self.encrypt_password_entry.grid(row=7, column=0, sticky='ew', pady=(0, 15))
        
        # Action button
        tk.Button(self.content_frame, text="Encrypt and Hide", command=self.encrypt_file,
                 bg="#4CAF50", fg="white", activebackground="#45a049",
                 font=("Arial", 11, "bold"), pady=8).grid(row=8, column=0, pady=15)
        
        # Status message
        self.encrypt_status = tk.Label(self.content_frame, text="", bg=self.bg, fg="#4CAF50",
                                       font=("Arial", 9))
        self.encrypt_status.grid(row=9, column=0)
        
        self.content_frame.columnconfigure(0, weight=1)
        
    def show_decrypt_ui(self):
        # Stego image
        tk.Label(self.content_frame, text="Stego Image:", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        image_frame = tk.Frame(self.content_frame, bg=self.bg)
        image_frame.grid(row=1, column=0, sticky='ew', pady=(0, 15))
        
        self.decrypt_image_entry = tk.Entry(image_frame, bg=self.entry_bg, fg=self.fg,
                                            font=("Arial", 10), insertbackground=self.fg)
        self.decrypt_image_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(image_frame, text="Browse", command=self.browse_decrypt_image,
                 bg=self.btn_bg, fg=self.fg, activebackground=self.btn_active,
                 font=("Arial", 9)).pack(side='left', padx=(5, 0))
        
        # Output location (optional)
        tk.Label(self.content_frame, text="Save As (optional):", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        output_frame = tk.Frame(self.content_frame, bg=self.bg)
        output_frame.grid(row=3, column=0, sticky='ew', pady=(0, 15))
        
        self.decrypt_output_entry = tk.Entry(output_frame, bg=self.entry_bg, fg=self.fg,
                                             font=("Arial", 10), insertbackground=self.fg)
        self.decrypt_output_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(output_frame, text="Browse", command=self.browse_decrypt_output,
                 bg=self.btn_bg, fg=self.fg, activebackground=self.btn_active,
                 font=("Arial", 9)).pack(side='left', padx=(5, 0))
        
        # Password
        tk.Label(self.content_frame, text="Password:", bg=self.bg, fg=self.fg,
                font=("Arial", 10)).grid(row=4, column=0, sticky='w', pady=(0, 5))
        
        self.decrypt_password_entry = tk.Entry(self.content_frame, show="*", bg=self.entry_bg, 
                                               fg=self.fg, font=("Arial", 10),
                                               insertbackground=self.fg)
        self.decrypt_password_entry.grid(row=5, column=0, sticky='ew', pady=(0, 15))
        
        # Info text
        tk.Label(self.content_frame, text="Leave 'Save As' empty to use original filename",
                bg=self.bg, fg="#888888", font=("Arial", 8, "italic")).grid(row=6, column=0)
        
        # Action button
        tk.Button(self.content_frame, text="Extract and Decrypt", command=self.decrypt_file,
                 bg="#2196F3", fg="white", activebackground="#0b7dda",
                 font=("Arial", 11, "bold"), pady=8).grid(row=7, column=0, pady=15)
        
        # Status message
        self.decrypt_status = tk.Label(self.content_frame, text="", bg=self.bg, fg="#2196F3",
                                       font=("Arial", 9))
        self.decrypt_status.grid(row=8, column=0)
        
        self.content_frame.columnconfigure(0, weight=1)
    
    # File browser dialogs
    def browse_encrypt_file(self):
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.encrypt_file_entry.delete(0, tk.END)
            self.encrypt_file_entry.insert(0, filename)
            
    def browse_encrypt_image(self):
        filename = filedialog.askopenfilename(title="Select PNG image",
                                             filetypes=[("PNG files", "*.png")])
        if filename:
            self.encrypt_image_entry.delete(0, tk.END)
            self.encrypt_image_entry.insert(0, filename)
            
    def browse_encrypt_output(self):
        filename = filedialog.asksaveasfilename(title="Save stego image as",
                                               defaultextension=".png",
                                               filetypes=[("PNG files", "*.png")])
        if filename:
            self.encrypt_output_entry.delete(0, tk.END)
            self.encrypt_output_entry.insert(0, filename)
            
    def browse_decrypt_image(self):
        filename = filedialog.askopenfilename(title="Select stego PNG image",
                                             filetypes=[("PNG files", "*.png")])
        if filename:
            self.decrypt_image_entry.delete(0, tk.END)
            self.decrypt_image_entry.insert(0, filename)
            
    def browse_decrypt_output(self):
        filename = filedialog.asksaveasfilename(title="Save decrypted file as")
        if filename:
            self.decrypt_output_entry.delete(0, tk.END)
            self.decrypt_output_entry.insert(0, filename)
    
    # Encryption and key derivation
    def derive_key(self, password, salt):
        """
        Turn password into encryption key using PBKDF2
        
        We use 100,000 iterations which is a good balance between security
        and performance. Feel free to increase this for more security,
        but it will make encryption/decryption slower.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, password, filename):
        """
        Encrypt data using AES-256-GCM
        
        We store the filename inside the encrypted data so users don't have
        to remember what the original file was called. If you want to add
        metadata like timestamps or file attributes, this is where to do it.
        
        Format: salt(16) + iv(12) + tag(16) + ciphertext
        Ciphertext contains: filename_length(2) + filename + actual_data
        """
        salt = secrets.token_bytes(16)
        key = self.derive_key(password, salt)
        iv = secrets.token_bytes(12)
        
        # Store filename with the data so we can restore it later
        filename_bytes = filename.encode('utf-8')
        filename_length = struct.pack('>H', len(filename_bytes))
        data_with_filename = filename_length + filename_bytes + data
        
        # Using GCM mode because it provides both encryption and authentication
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data_with_filename) + encryptor.finalize()
        
        return salt + iv + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data, password):
        """
        Decrypt data and extract original filename
        
        GCM mode will automatically verify the authentication tag,
        so if the password is wrong or data is tampered with,
        this will raise an exception. No need for separate verification.
        """
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        key = self.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Extract the original filename that was stored during encryption
        filename_length = struct.unpack('>H', decrypted[:2])[0]
        filename = decrypted[2:2+filename_length].decode('utf-8')
        data = decrypted[2+filename_length:]
        
        return data, filename
    
    # Steganography functions
    def embed_data_in_image(self, image_path, data, output_path):
        """
        Hide data in image using LSB steganography
        
        We modify the least significant bit of each RGB channel.
        This makes imperceptible changes to the image (like changing 152 to 153).
        
        For developers: If you want more capacity, you could use 2 LSBs per channel,
        but this starts to become visible. You could also add error correction codes
        to make it more robust against minor image modifications.
        """
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        width, height = img.size
        max_bytes = (width * height * 3) // 8
        
        # We prepend the data length so we know how much to extract later
        data_with_length = struct.pack('>I', len(data)) + data
        
        if len(data_with_length) > max_bytes:
            raise ValueError(f"Data too large! Max: {max_bytes} bytes, Got: {len(data_with_length)} bytes")
        
        # Convert all data to binary string
        bits = ''.join(format(byte, '08b') for byte in data_with_length)
        
        # Replace the LSB of each color channel with our data bits
        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            
            # Clear LSB and set it to our bit using bitwise operations
            if bit_index < len(bits):
                r = (r & 0xFE) | int(bits[bit_index])
                bit_index += 1
            if bit_index < len(bits):
                g = (g & 0xFE) | int(bits[bit_index])
                bit_index += 1
            if bit_index < len(bits):
                b = (b & 0xFE) | int(bits[bit_index])
                bit_index += 1
            
            new_pixels.append((r, g, b))
        
        new_img = Image.new('RGB', (width, height))
        new_img.putdata(new_pixels)
        new_img.save(output_path, 'PNG')
    
    def extract_data_from_image(self, image_path):
        """
        Extract hidden data from image
        
        We read the LSB of each color channel to reconstruct the hidden data.
        First 4 bytes tell us the total length, then we read exactly that much.
        """
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        
        # Extract LSB from each color channel
        bits = ''
        for pixel in pixels:
            r, g, b = pixel
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)
        
        # First 32 bits contain the data length
        length_bits = bits[:32]
        data_length = struct.unpack('>I', int(length_bits, 2).to_bytes(4, 'big'))[0]
        
        # Extract exactly the amount of data that was stored
        data_bits = bits[32:32 + (data_length * 8)]
        
        # Convert binary string back to bytes
        data = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            if len(byte_bits) == 8:
                data.append(int(byte_bits, 2))
        
        return bytes(data)
    
    # Main action functions
    def encrypt_file(self):
        """
        Main encryption flow
        
        We run this in a separate thread so the GUI doesn't freeze during
        processing. For very large files, you might want to add a progress bar.
        """
        file_path = self.encrypt_file_entry.get()
        image_path = self.encrypt_image_entry.get()
        output_path = self.encrypt_output_entry.get()
        password = self.encrypt_password_entry.get()
        
        if not all([file_path, image_path, output_path, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File to encrypt not found")
            return
        
        if not os.path.exists(image_path):
            messagebox.showerror("Error", "Cover image not found")
            return
        
        def process():
            try:
                self.encrypt_status.config(text="Working...", fg="#FFA500")
                
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                original_filename = os.path.basename(file_path)
                
                # First encrypt, then hide in image
                encrypted_data = self.encrypt_data(file_data, password, original_filename)
                self.embed_data_in_image(image_path, encrypted_data, output_path)
                
                self.encrypt_status.config(text=f"Success! Saved to: {output_path}", fg="#4CAF50")
                messagebox.showinfo("Success", f"File hidden successfully!\n\nOriginal: {original_filename}\nOutput: {output_path}")
                
            except Exception as e:
                self.encrypt_status.config(text=f"Error: {str(e)}", fg="#FF0000")
                messagebox.showerror("Error", str(e))
        
        threading.Thread(target=process, daemon=True).start()
    
    def decrypt_file(self):
        """
        Main decryption flow
        
        If no output path is specified, we use the original filename that
        was stored during encryption. This is super convenient for users.
        """
        image_path = self.decrypt_image_entry.get()
        output_path = self.decrypt_output_entry.get().strip()
        password = self.decrypt_password_entry.get()
        
        if not all([image_path, password]):
            messagebox.showerror("Error", "Please provide image and password")
            return
        
        if not os.path.exists(image_path):
            messagebox.showerror("Error", "Stego image not found")
            return
        
        def process():
            try:
                self.decrypt_status.config(text="Working...", fg="#FFA500")
                
                # Extract from image, then decrypt
                encrypted_data = self.extract_data_from_image(image_path)
                decrypted_data, original_filename = self.decrypt_data(encrypted_data, password)
                
                # Use original filename if user didn't specify one
                if not output_path:
                    final_output = original_filename
                else:
                    final_output = output_path
                
                with open(final_output, 'wb') as f:
                    f.write(decrypted_data)
                
                self.decrypt_status.config(text=f"Success! Saved to: {final_output}", fg="#2196F3")
                messagebox.showinfo("Success", f"File extracted successfully!\n\nOriginal: {original_filename}\nSaved as: {final_output}\nSize: {len(decrypted_data)} bytes")
                
            except Exception as e:
                self.decrypt_status.config(text="Error: Wrong password or corrupted data", fg="#FF0000")
                messagebox.showerror("Error", "Wrong password or corrupted data")
        
        threading.Thread(target=process, daemon=True).start()


def main():
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()