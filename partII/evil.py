#!/usr/bin/python
# -*- coding: ISO-8859-1 -*-
blob = """       �oJ�S�~9��ĴO��R�\QA5~Bέ�?���ꂋ%o������?���b������7OT�l�mM4P`�
�\�f�8��/�$�����,1�N^��wƃ�(�QZ�8���[�m��VgS�U�41"""
from hashlib import sha256
if sha256(blob.encode()).hexdigest() == "9735ba281509c56df4a879b7bb37eb0131e9065beedef3b8eca380df70edcbaa":
    print("I come in peace.")
elif sha256(blob.encode()).hexdigest() == "0837c575c6f8e62842de29e8a88f4c43fc8abc322dbbc9040934b6353317e40f":
    print("Prepare to be destroyed.")