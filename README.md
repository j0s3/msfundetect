Msfundetect
===========
Msfundetect is a ruby script that undetects payloads and it can be used smoothly with Metasploit's msfpayload for getting 0/56 detections in virustotal.


Method
======
Msfundetect is based in "hyperion" packer (by Ammann, 2012, http://nullsecurity.net/papers/nullsec-pe-crypter.pdf).
Instead of using hyperion's original approach of bruteforcing an AES key in order to decrypt the payload, msfundetect method consists in cracking the entire payload with crc16, which is done by creating a self unpacking shellcode constructed with the crc16 hashing function and the crc16 hashed payload.


Result
======
Msfundetect generates undetectable standalone shellcode (which may be used for example in buffer-overflow or use-after-free attacks).
It also has the option to make an executable, which is also undetectable.


Verification
============
Msfundetect result can be verified in virustotal (which takes some minutes) using 'vt' option: msfundetect -t vt


Usage
=====
msfpayload windows/exec cmd=calc r | msfencode -e x86/alphamixed bufferregister=eax -t raw | msfundetect -t x > j.exe