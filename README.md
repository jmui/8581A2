# 8581A2

**FSCT 8581**

**A2 - Building an Electronic Cash Solution**

**Justin Mui**

---

**Requirements**

PyCryptodome

https://pycryptodome.readthedocs.io/en/latest/src/installation.html

`pip install pycryptodome`

---

Encryption uses AES in CBC mode

Key is generated using SHA-256

EMD token is generated in bank.py as a JSON string, then used in wallet.py to withdraw money.

Tokens to sync wallets and to send/receive funds are also JSON strings.

"FSCT8581" is used to generate the bank's key since I could not hard code the hex string from the assignment instructons. PyCryptodome's AES implementation appears to need an "Crypto.Hash.SHA256.SHA256Hash" object.

