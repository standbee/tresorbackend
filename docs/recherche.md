## Salt and Pepper Hashing

Hashing is the process of converting data into a fixed-length string of letters and numbers. Data is converted into these fixed-length strings, or hash values, by using a special algorithm called a hash function.

Hashing is used to encrypt sensitive data like passwords in order to keep them secure during transmission over the internet.

The hash function takes the password as input and produces a unique output: the hash value. This hash value is then stored in a database instead of the actual password.

### Salt

Hashing is not foolproof and can still be cracked using rainbow tables. This is why 'salt' can be added - which is a random string of characters that is included in the password before the hashing process. It is then stored alongside the hashed password in the database. This means that even if two people have the same password, their hash values differ from each other.

### Pepper

Another layer of security on top of salting is 'pepper'. Pepper is a random, unique string of characters that is included in the password before hashing, just like salt. But in this case, the pepper is not stored along with the password, but rather separately and is kept secret.


## Further encryption techniques
### PBKDF2
Password-based Key Derivation Function Along with salting and peppering, this algorithm can be used to further increase the security of an application's password encryption. It is a high-level algorithm that internally calls a pseudo-random function to process input (the salted, peppered password).


---

## Password Hashing Implementation

### Requirement

- Beim Registrieren wird das Passwort als Hash in der DB gespeichert.
- Der Hash verwendet Salt und Pepper.
- Beim Anmelden (login) wird das Passwort erneut ge-hashed und mit den Hash in der Datenbank verglichen.
- Bestehende Klartext-Passwörter in der DB müssen ersetzt werden.

### Steps

- Research hashing, salting, and peppering.
- Add Salt and Pepper Hashing to the prepared file, "PasswordEncryptionService.java"
- Testing











## Secret Encryption Implementation

### Requirement

- Secrets in der Datenbank müssen verschlüsselt gespeichert werden.
- Beim Lesen der Secrets müssen diese entschlüsselt werden.
- Der Schlüssel soll für jeden User unterschiedlich sein.

## Steps

- Research encryption and AES encryption
- Add encryption, decryption, and other necessary functions to the prepared file, "EncryptUtil.java"
- Testing

[//]: # (ejfbhedjfberikbvfverf)

![Alt text]( "a title")