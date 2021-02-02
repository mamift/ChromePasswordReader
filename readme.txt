The project aims to get the saved passwords in the Chrome.

New Chrome version (v80.0 & higher) uses Master Key based encryption to store your web login passwords.
Older versions use DPAPI directly to encrypt the passwords.

The project is facing an 'BCrypt.BCryptDecrypt(): authentication tag mismatch' while trying to decrypt the password which were encrypted using Master Key based encryption.

Program.cs is the entry point of the solution which reads all locations having 'Profile' directory in AppData location for Chrome as well as all 'Login Data' files.

The code treats the 'Login Data' file as SQLite Database file and tries to query 'logins' table for url, username and password.
It then checks the first 3 characters of the password to check the encryption method used. If character equal 'v10' or 'v11', then Master Key based decryption method is used, otherwise simple DPAPI decryption is used.
