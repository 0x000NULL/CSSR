# Bonus- Cryptogrpahy (e-mail)

Two of the core principles in the cyber security model is Confidentiality and Integrity.  A core technology to each of these is Cryptography.

# Cryptography

Cryptography can be defined as "the art of writing or solving codes", but more specifically to our cause, it is used to secure communications (confidentiality) and prove that data has not changed in any way (integrity).  On a very low level, cryptography is the ability to run a math function on information to make it unreadable, and to be able to run another math function on the information to return it to readability.

When we want to secure our communications, we will use cryptography encoding, or encryption, to make the message look like random garbage that someone picking up the message will not understand with out knowing the encryption method or some shared key.

An example of a simple encryption is the message below.

    Unir lbh gevrq gheavat vg bss naq ba ntnva?

To an untrained eye, it could be a bunch of random letters, but a cryptanalyst would use the frequency of the letters and spacing to work on decoding.  (If you are interested in what the message says, and you are on the Discord server, you can use the "!hint cipher" command to get hints on how to decrypt the message.)

## Hashing

Hashing is a subset of cryptography that is missing one key concept; the ability to reverse the encryption.  You may wonder if this is useful, and it is useful for verifying the integrity of information. The math functions that are used in hashing tend to be very fast, and thus can come up with a 'hashed' value quickly.

If you have a file on your computer, and your friend has a file with the same name on their computer, you could each open the file and compare the contents to see if they are exactly the same.  But if the file was very large, or used data that you are unable to read, then it is not feasible to try to compare with your eyes.  This is where hashing comes in.  You each would run the same hash function on the file, and compare the hash value that is produced.  If both values are the same, then the file is most likely exactly the same.

Hash functions are publicly available and standardized in the values that they produce.  The most common (and slightly vulnerable) is a MD5 hash.  The most common use of this  hash is to verify that downloads completed successfully.  There are free programs that can get the hash value, or most operating systems will have it built in.  Examples include:

- WinMD5 - Free program to download
- Windows Powershell command of Get-FileHash
- Linux command of md5sum

Hashing is something we will have to do in the first challenge.
