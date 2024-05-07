# AES Application
This repository contains a simple application, written in Python and inspired by Veracrypt, that encrypts and decrypts a selected file via AES. 
The GUI was implemented using Tkinter, a popular and built-in Python library.

# Important Note 
- This program is a prototype, so there exists many bugs, and at the same time, its functionality is not there yet
- As such, it requires more testing  
- I am unable to upload the entire project, for some reason, which I would do later 

# Features to be Added  
- [ ] A progress bar when encrypting larger files 
- [x] A dialog display upon successful or unsuccessful encryption or decryption
- [x] Possible support for more complex file extensions, e.g. .docx, etc.

# Fixes to be Added Later 
- [x] Fix the size of the password window
- [x] Some file extensions cannot be decrypted properly  

# Usage 
## Encryption
Select a file, then encrypt it, and provide a key. 

## Decryption
Likewise, select a file, then decrypt it, and provide the exact key.

# Dependencies 
- Python 3.x
- pycrptodome  
- cx_Freeze

# Building the Project 
- Download the dependencies 
- Download cx_Freeze
- Execute the command in terminal: "python setup.py build"

# Final Project for Information Assurance and Security
This application was developed as one of the applications proposed for the final project of Information Assurance and Security. It demonstrates the implementation and functionality of cryptography using AES.



