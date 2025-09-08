# -Personal_Diary
This is a project thanks to which you can add a password to your diary, which allows you to hide it from prying eyes
This project is divided into two parts: executable code and encryption library. The encryption library implements: sha256, hmac for sha256 and pbkdf2 for sha256.
The executable part of the code has the following architecture:
1 - we create two salts for pbkdf2: aut_salt, enc_salt. The first one is needed to generate a hash based on the password. The second one is needed to decrypt the session key.
2 - we ask the user to enter a password, based on which the hash will be generated via pbkdf2 and then saved as kdf_hash.
3 - we ask to enter the key, and if it is our first time, we simply create hmac_hash. Otherwise, we use hmac to check the salts and hashes for integrity.
4 - If it is our first time, we simply create a notepad and session key file, and finish the program. Then the program asks what we want, to decrypt or encrypt:
If we decrypt, we simply create a new password based on the key and password, which goes through pbkdf2 and decrypts the session key, and then the notepad itself is decrypted based on it.
If we encrypt, we generate a new session key, which is comparable in size to the size of the notepad itself, and encrypt based on the password and key, as was said above.
Data should be written between decryptions in blocknote.txt.
ALL.
