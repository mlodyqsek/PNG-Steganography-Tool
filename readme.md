# PNG Steganography Tool

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)

A simple and secure tool for hiding encrypted files inside PNG images using LSB steganography and AES-256-GCM encryption.

## Features

- **Strong Encryption**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations)
- **Invisible Hiding**: LSB steganography makes changes imperceptible to the human eye
- **Filename Preservation**: Automatically stores and restores original filenames
- **User Friendly**: Clean dark mode GUI, no command line knowledge required
- **Cross Platform**: Works on Windows, Linux, and macOS
- **Open Source**: Free to use, modify, and contribute

## How It Works

The tool combines two security techniques:

1. **Encryption**: Your file is encrypted with AES-256-GCM using a password-derived key
2. **Steganography**: The encrypted data is hidden in the least significant bits of the image pixels

The result is a normal-looking PNG image that secretly contains your encrypted file. Without the password, the hidden data is both invisible and unreadable.

## Installation

### Requirements

- Python 3.7 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Dependencies

```
Pillow>=10.0.0
cryptography>=41.0.0
```

## Quick Start

### Try It Out

We included a test file to help you get started:

- **File**: `img.png` (sample stego image)
- **Password**: `test`

Run the application and use the decrypt mode with this file to see how it works.

### Running the Application

```bash
python stego_tool.py
```

### Encrypting a File

1. Select "Encrypt File" mode
2. Choose the file you want to hide
3. Select a PNG image to use as cover
4. Choose where to save the output image
5. Enter a strong password
6. Click "Encrypt and Hide"

The output image looks identical to the original but contains your hidden encrypted file.

### Decrypting a File

1. Select "Decrypt File" mode
2. Choose the stego image
3. Enter the password (leave "Save As" empty to use original filename)
4. Click "Extract and Decrypt"

Your original file will be extracted and decrypted.

## Security Features

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Random Salt**: Unique for each encryption
- **Random IV**: 96-bit initialization vector
- **Authentication**: GCM mode provides built-in tampering detection

### Steganography

- **Method**: LSB (Least Significant Bit) substitution
- **Capacity**: Approximately 1 byte per 8 pixels
- **Imperceptible**: Changes pixel values by at most 1 (e.g., 152 to 153)
- **Format**: PNG only (lossless format preserves hidden data)

## Image Capacity

The amount of data you can hide depends on image size:

| Image Resolution | Approximate Capacity |
|-----------------|---------------------|
| 1920x1080       | 777 KB              |
| 1280x720        | 345 KB              |
| 800x600         | 180 KB              |
| 640x480         | 115 KB              |

Formula: `capacity = (width * height * 3) / 8` bytes

## Important Notes

### Do's

- Use PNG images only (JPG compression destroys hidden data)
- Use strong, unique passwords
- Keep your stego images safe from lossy re-compression
- Test with small files first

### Don'ts

- Do not re-save stego images in JPG format
- Do not edit stego images in image editors
- Do not forget your password (data is unrecoverable without it)
- Do not use the same password for multiple files

## Technical Details

### Data Format

**Encrypted Data Structure:**
```
[16 bytes salt] [12 bytes IV] [16 bytes auth tag] [variable length ciphertext]
```

**Ciphertext Contents:**
```
[2 bytes filename length] [variable filename] [variable file data]
```

**Image Storage:**
```
[4 bytes data length] [encrypted data hidden in pixel LSBs]
```

### Steganography Algorithm

Each byte of data is split into 8 bits. Each bit replaces the least significant bit of a color channel (R, G, or B). For example:

```
Original pixel: RGB(152, 200, 89)
Binary: 10011000, 11001000, 01011001

Hide bits: 1, 0, 1
Result: RGB(153, 200, 89)
Binary: 10011001, 11001000, 01011001
```

The change from 152 to 153 is invisible to the human eye.

## Contributing

Contributions are welcome! Here are some ideas:

- Add progress bars for large file operations
- Implement compression before encryption
- Support for batch processing multiple files
- Add image quality comparison metrics
- Create command-line interface
- Add unit tests

Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate privacy purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

## Acknowledgments

- Uses the excellent [Pillow](https://python-pillow.org/) library for image processing
- Uses [cryptography](https://cryptography.io/) for secure encryption
- Inspired by classical steganography techniques

## FAQ

**Q: Can someone detect that an image contains hidden data?**  
A: Statistical analysis can sometimes detect steganography, but it requires specialized tools and expertise. Casual observers will not notice anything unusual.

**Q: What happens if I use the wrong password?**  
A: Decryption will fail completely. AES-GCM authentication ensures that wrong passwords are detected immediately. No partial or corrupted data will be produced.

**Q: Can I hide multiple files?**  
A: Currently, the tool supports one file at a time. You can zip multiple files together first, then hide the zip file.

**Q: Why PNG only?**  
A: PNG uses lossless compression, so the hidden data survives intact. JPG uses lossy compression which destroys the hidden data. Other lossless formats like BMP would also work but PNG is most common.

**Q: Is this secure enough for sensitive data?**  
A: The encryption (AES-256-GCM) is military-grade and considered secure. However, steganography adds security through obscurity, not cryptographic strength. Always use strong passwords and keep your stego images safe.

## Support

If you encounter any issues or have questions:

- Open an issue on GitHub
- Check existing issues for solutions
- Contribute improvements via pull requests

---

Made with Python. Released under MIT License.