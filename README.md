msfundetect
===========
Msfundetect is a ruby script that undetects payloads and it can be used smoothly with Metasploit's msfpayload for getting 0/56 detections in virustotal.


method
======
Msfundetect is based in "hyperion" packer (by Ammann, 2012, http://nullsecurity.net/papers/nullsec-pe-crypter.pdf).
Instead of using hyperion's original approach of bruteforcing an AES key in order to decrypt the payload, msfundetect bruteforces the entire payload using an optimized crc16, which generates a self unpacking shellcode containing the crc16 hashing function and the crc16 hashed payload.


result
======
Msfundetect generates undetectable standalone shellcode (which may be used for example in buffer-overflow or use-after-free attacks).
It also has the option to make an executable, which is also undetectable.


verification
============
Msfundetect result can be verified in virustotal using 'vt' option: msfundetect -t vt

usage
=====
msfpayload windows/exec cmd=calc r | msfencode -e x86/alphamixed bufferregister=eax -t raw | msfundetect -t x > j.exe