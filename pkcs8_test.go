package pkcs8_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"github.com/youmark/pkcs8"
)

const rsa2048 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBMF0LikTFOU/T
8DUDSvORootvhUD67f6AXmEnntfXRvQ3O91+qt40tevS8JtFaq4gKxugRjjZRtni
50aUGcEZ4leq3DboBL9XH089IEmxxLbJeJIXxgPeRHrXRINvUSspwRrJkX6fnXyi
MdRhqdH2tG1yrXKkt9UvdSHfRYimDcJ+ry2zYlcbz9aoLDO1vEdS/IBu0jXAZ/Z/
xaEVfkoWMzZM2SU+lfJeyzobii00VXGuSQKnI8E/e16kDpBXJ6PFSm6EyZmAad6O
f+B9d/ZEXGQlbaooG54v5sGj54mg7m/75qMaxL2H8NER31gAeyvoyovfXI0vbswH
8AozxGwDAgMBAAECggEAautIY62nt/urKaIExQjDWvO59gOq3fW/5+3UGWh5DqUv
Xi5cvND2X/fbR4hwdu++5QDWrlKO/fmPd1wGnMrQK3IwkNiF7s1J1H74jN0EzEUR
4NlBCbVGyMnfrqo1j/M9T0OXfr1udgpkQyQO5epl0QM0m8ZQ78bqTvSlxXsnULbQ
py0Tx0uCWaP6FzDsZ+t2rj/SVH7hQNf8ITfQJhVol/n5Hza4+NRfp/DPXWZEvPlo
GeMs9PDCa16tw8wI9EUnmFaeFlmtJPdTs5rVo9Ya/zmtoxN6AGTCG0IE6YRvh3Qn
jttIp2QitOSBKmXpu1ZI6UTtimGgnfiJKK1BGVaMOQKBgQDfF6ZBMY/tLmDg1mgS
QQKAOWMB0/3CvzcM96R0VACO2vr1BbePMXQQ/i27rD001Xl2wNTsETRk1Ji6btwQ
64m4uxRSZCJmYyBAcJjfBtMWIDiihQTL55NFTd9YIPmqGmbj1ASQgtpQR5Cq/5YR
9Vu0kTxMmADoiq1tR2VGZeScnwKBgQDdr4ITDFGSpqWKnyHQaQgTIW4uxQ5pQKIx
aKbCNZOtSgJfqUCY+8gJMkFOtQzawrburD4qllFxdqhHLiXSx6/8zSTrsiexml2i
7HxUZaSmn5Q4HFNngKKHXd4NGsWp237k8fJ2953KX89yEov8FpIiq6qvZH/LS8DN
+GORAPSSHQKBgCHobUuRZefN2cmyrOTBXsjwb/zyJKq593sQFL3dmqwb2nLtaIXq
JVMD3x2cQz1JiQmkq3gp8UW2DnSfrvEfa7JZNPCE6bmYLWm9825KkkDVquYAw8be
LsMk3+J8OJZDJwpPylXQnbAAAJwM9tlJ6qNaQ8j8fX7avRtT86+sgv/PAoGABjJp
yG6HuTm/Vuir4U+OUjqVAemwRXDxF8B9KOCmiCmRd2sbyyr+pIMrIDAfc94Njw5x
jm81R56xhYvcss+yM7boWU5ZnbVa+LrznshYme/MDOV9z17hLDeLhYJCFEV2fp/k
zz6MwqN7AQ1TrHBVFXMHCnAcwmoTsa5H2j3UmGECgYEAvvJ+o5+FPnBs+VU5FJxF
fAGFpF3AwfbSCm2ARZOxMHAkpsz/FBXlo+rVZv6loTKTPQFMxIB15il7ls0CGI9q
6UaZ5hkKjEOQUW8UYc8Cv0xpSkcuxcGrWzw4AMdc84XXi6F1+48ab9Gt0pN3tgUG
qg+KU+JDsQLHHmykZ92cHPA=
-----END PRIVATE KEY-----
`

const encryptedRSA2048aes = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIrrW09+9XumECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAxglavSPtrKNsM9cDXmrS1BIIE
0Gy226c9+zxZ8jUsUIbDdsq1mPbqAWs1xImAj4nA7NMv6G/5QH9CrsmB+4r4GIiy
CafN1W9YvFg3SISUbe+h156Pt2iKoZlVCbSa4XVo4diwmjloZIHM4Jk0Pu28CbJo
QDVwPCuWMKppkfwr63RT+FBSfBEBaRCi4eXz6tOcMduBOlaiQvSREvDCCOeY9gja
RgvyUa2Hf8oHNkSG9yXoMrvz0FayMWK/i7LU+2NqiPZVTvfGkqNkJJF/M7INKgLs
d6A1hgyA7HVv4czQOPQJCArXeCycI1EJ4uSthJxqd/iYX0z52Tfa7q/0oAZ4HZt+
wmcov8GwqfAg7Cu9soifYwfMYTghXOX2UKmQa/0UNK5ibj5cC9+oA09Ucx5twKDs
nwSGEIb+7qNhZSRtEXtOL7bxQL8PUvAXWrTXluvZ+bv/9S53XYPL4E95rrLnTF/L
csEYleNIpY/6HkPFtqPZiWCsVUZep9uPjZo29kh/246yKBFjsw5mXtm1S6ha4Xb9
gUxqKQiWe9+tCkPHRVo2KJX1H4Al7UB9GqDR5oUhIayp6nYCeI/dLwPpikq1F8HO
iJva/qV2iltxwyQHhEenyM9TPkPawqOOUKvDd1hZR0wzABcC3koLtwwKyEGzQPPW
bxp5GBim9Pu/EGWY1d1H38eVu44jRP/3ONk8wvZcsIbn6U8bOeToUFmcjuuQ3cxf
pDUruIA9PjWL9Se6TI3CytTUCbCb4bKRP+eE0B2LPwq6+dyvcY2yidYj9C2D25tb
F+E1Wr7ro97OXQ8grMWwrTpZ9rUzmz5wzYWmOFaKJRiepkuUpx4HWl+fKn5r5LyV
+cyYoSjApNgHe/9Pz7mNXNdeSmWcn4BVs1XgKi1MiJNWn5tNlKB3kz1kgraKOWbs
9/dspegd5fQ6Lzvlt7CsJh/I76rE+90LAbXWVlQ/jm/4jrWownjW1oVIj0Xfxx7i
UlmtTFoCIvNWRyoyK5pfL0JvxOtd5leHZniJoww0CPKYS0mibxYLc883Q5Hq5ZH/
C7iBJN0aDJfVfkl0o4EQWaWQS0rAInhe7xTHmFFe5NP9lVTEwQt+C/fz7qalHe9P
ulV8MsT/vg2/9twvxKbVCSzaDyta/TyhX76LTULprPr6ahDhP9rybmmK548m86kZ
IxWdmed7Pt3YPeEImoLBoXh8eaWpYDlX2Be5/eqjw2wbg6srBKoA7swSkMsFXm5q
+HgF4X6R9lfmLjs/UMOi9SM6ODh4xgq1DxX+bJZLfJwXj90i56Ij8OhjcBJ+DwUi
ntosYkXp6lMZIyfI3jWG4IZwE9nt8oXJZfUtIU5mYF9DAV92fRwm1mCLMx0iznv1
bvCu7yJ51nWB3xkIOqCYbzbREWmL+6/akGOqu1KDrFKBu0IyAqUWt0XrY3b4V5jm
WjTXywDkCcGC6W0t4yhu1Yz8QhE5Giw2PHwwZ3940QZQsFcBM6RJOcnkbYTu8TFm
7s9ZItSShwAN/i1nN1daF9lgdm4WKHWd/jqHIgl2NijiDgb5F5YaWgurKg9tOrEK
oGJlPmBUiNynhqcz69ljjW6q4U2cfF4g6Onl2sucLdsFXejgVdsKBVXw+gjGr2TS
lgmeHTcvZmTShvbN/TrHETjO7jEB4V2I4a4L7uybuWF/
-----END ENCRYPTED PRIVATE KEY-----
`

const encryptedRSA2048des3 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIKXB+OWAc6pwCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECCeQ2z+ohlaTBIIEyAbgxv69udAD
N0JzM0+E/dYKTRxEVED1cyY+fcROfxkJvT3FOOWS65vaPo5i8n0e7pFHvm/ezkoL
mNRYhoyd45pog4ALJ6O03bUBTLJPiowz90uHC7GWQelMl7LeNyX/7/5s2jOpgW82
oB6JizF9SjZzCTzKTmZLOAz3GjIERWHmoIczy40nxP7zmHzVrxTp1V6gnzxgUIuA
X/7FTMRlWvEbX9gzODx7stI/5/bLla1Y7PDWEs2aJCnsN7pXJSd0Ry2/iBnQKe6n
p4RW7jRAiFTGXbR1E5ZoFsSUs0K9JLEJA+kq6x+smRGxioV3I/r6MLaeumNZ37Bx
9OfiJAWk0Ei9EUjM4ZLWjnhgRyI2mThEXTbCevv2GonwG9G968QEMjfbXcLA6Opt
0mmRutT6IgvflEZRi9BlmCGOecNHl+cojVCwmAPZKkk2e9lZe+x9+TXW66GJVFiK
6BlgRwTcNPKePCYWPjsV5wUZACq0Y61nksBViyRUFsEkEEYMXIbh6bbUTTlJg/tk
tCp/LF9oTf1XacJ8a/s6oLuz95R07u9E/liibzVavK0nVNSR5Xdo7QDivWxnaSLd
wt8qUOnVbW0eSyq2BAKK7yvZfhz44D9WS8M8jp8gwj7Eti81LGqeh5IvqekDYmoz
BFiY24PnRcZnpETA/e6v5dNrpE/OLHmdY1ag6aifIJCc1UG84Oi/nPBTZ7eHLGCd
Kn4/9xdCVHd4077Qx9JLW9LutZXkqYaBckOEHtvaMfyWUaXiNty/N5RECGvn5wmM
dwC6td6CqtojiHOB7GAUiwjHgbQLpNoIz1BiVTIo1eoD32+4RHYUxNmhsk0r22Zf
ZnfnKBGgV7KKNKP3eFQnzSeNE0qFd5AtSpeJX0G0IsbuvXOE/7P0pj7DhD4HoYS7
Mf2za6Wm/CVWNM4ekc3MsKb9D+ogzdQ4VYI2mzBdLulrYvfPCE6SHZlZ+ePE4LSr
jexB6LYLZJU7Bxnslt9E/mjSzWHctF9LhHf7sl7NUhCHdDvij6Hd0l4+noQlDTtd
rnXgL9fTjSfaVDv3Rt+AmNN9Cu9Y1FSBLYMe8LfGXXUPg86bTbGk3uFjkyIY3hE2
/Kz1re4KXdDdjYe4ja5qZK8fWx0704NkzH1UO/HMd4Cnx3agyVeyJVG3iRSIesRG
vI1ESJMMv1+MMGiWwRzHYvv7yrqp2steAVwjGu26/s1vwkZrvy8SjzYAXo1RLT9o
cNnlPra6N7xReSohOibAp0kx1d81JqvEOvJIhR7KDXSRutgIPlqQgHXtmDW/VlCb
w05Ptg3SXaCE0+pY0T+FYHusA3JEmyU0e629Ed/dl/j7Xpynl1V6/ndf3gdRGX0l
d2IGneJsnj8yvP0dUsB2l71W/ZIM3HERDLxP9JByyINCBQ1BFsN81qUXpj6vGYjb
hPyUmmsAGibXJOiGzmaP3nGgF9qbe1XiTRdbm2AZ3pEaJxkkFWsT+Yivz9yzZE0P
3/w14HvS94X/Z2+yDLtQQgsLNkfw/Gpc4O0GMnLuOl4KSaTA37IdJR2jOFP7LtHR
9Egbm93atZWSAyTO7OtZGmna6k6eGUsk8Dxp7cWOUkLf7C5sL6l3bBH7omlQHx9P
RIiDkxAd7hbpm4/C/DoUZQ==
-----END ENCRYPTED PRIVATE KEY-----
`

const encryptedRSA2048scrypt = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJTBPBgkqhkiG9w0BBQ0wQjAhBgkrBgEEAdpHBAswFAQIY6+u2Dcq3hwCAkAA
AgEIAgEBMB0GCWCGSAFlAwQBKgQQ6Kut7Q560w1e+fqSiF6uUgSCBNBWRJP19DiT
m/ZWEh4ukxTnrBpx59ATbuiBZjjty9vw/dkusUivNLsIoJDezuv4YxjxNx4zZsv+
vI5/gWT78XdF0XHgrRKjB0AvQ4rdVSUhV2/sxMa8P5bwE7NikovkzP1rM0cPCLRE
K5J81+pEOVKumJJg3jNtK18HtCiH0D4n276xK6fJ2BptA1BMNhlDkoz99kmwPfhg
gMiJxbcGrYHMvCZAL8towTRomI82fjRwpEtT8eZ7aLUALDM53JXzhiz/bO2cKCRx
4oLx6rChrqCTS4bZ++PPBS9klwW1kx5eMTGdv3IS+/Y7wvPtZ9jbwcjkSKpOsALv
h/6CzUuTo5dIPDaOidLLHS4bfgKCC/da/uuow/ET7K6KBOZ6kCnXi300D+hZE8cJ
GYjIQGVY3FtrtZx55hjeqyRsVrdKP0e83wNEnGgofsgeJ+H88zUxaMqIiz3e773M
zshNXcCko9jAgr8PwRg7ARPql+TcS3fJ+HPBA1mDlT4xMXyFOgckMkz8xR08EA0M
UcvtGAxLJYtsiMJigdrCI7lGmWZbj8tB2sS0JD95QsbR5CcsqzaELzoKMdOpG5MP
4ZdgHpeGNtw15aAIdxfoFGGcNgLiZ+y7BC0fM9xYAPARrb64A3e3gmsJ3ZKEkZzR
MbK9a08S+6VI68T9M0f3i53p/e09CYZ0TN3yMN/g/usxERzpji7zCjEYf6yuUeRF
c3ceVVaxldexAOV0dEIUq8xehUhvhV129/hUHUyqsx1XiURWSx2TRSjuZ3SE63Sc
LO81rijz4rFa69JXPGWNrzR0IS0CY8aMF79fwqpcLaRHIpfQLiIQ19qDHiipXCs/
ZLli5MZQZ7AHoXqbHBQOqhiT2LLEgeVF4uEi0qM1ULfmmZMoJQg+ugRXPEJR0fa0
ji6Hb/ZTDGwsdrNZGfTD4lJeiel3IPVcOzfeZqb6OsdkUSQzZZSvAET95qkKn/CN
diPkX96iYuhjcace/f8xLnVY3TJ6WRpDW9oBzVFEm5jXtlHhVltau2Qmoi28pthE
25QrNfoOs4qr2gaGA37VXSEW4yLU3jyqlP1esXxyEiqg9CKPnk/K/XxREjGJXElr
FQtRif9b4QDBrZc38Y5ct7x+Ce7llJ3kKslVdF2rbVEn4nPIHIqw8oKDv/6+CNwo
8O1B4u16WUqj2Th6hOQcmWb9Nb6Js5TSRtIJxrif6PTfTczSB9bZgU1fTxgr0tTI
AERJLqFA9dvCxAehWrlegsSOwvJ/E8FwbGJLhiJs6aFk1fJ6NPkp62UkmvBMDq1w
qYuwLSr920KrPsCYBa09Ldm9e88+nCQz5QWcJt2vvdIz0UQUqtsjUo8DWL0qNXgU
JVSRrfE+64II2sxt3/9oywLCk9DG+dcWZH6SRjSt7y9KhWfhdGq1S6Og1Mjc+U4A
L/TgycaVTBodGTmw5YlsbSBYzAwSBCaR7GLThhZqIlPrk6P3w8VZJ1B14nEcTP9Y
GVdcEOqE0mwNtWZYcuy1cqPj6g/p9NOmLOnT8HGbjw9qtdl+iEGN/ZDWfu+En7ES
Dv4v0MiWAMArKY8rAMWa9/phbWXVEtNz6RnJ460qxIax5GR0QPce3+lrswhmXSm4
RNXdI4NIGtOdg8zwuKI5AefoLlWjt56Pzg==
-----END ENCRYPTED PRIVATE KEY-----
`

const encryptedRSA2048pbeSha3Des = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6jAcBgoqhkiG9w0BDAEDMA4ECH5gHmdJa18CAgIIAASCBMiy74Yy5keszalY
FsTV3XE7LajhZs+qfK6TS7Sbtw+602mLORLkkZVS+U7ImjC7FD2BAMJ9aG3zrs16
zW7hjCljGzO07Rh/8THI0dSTuTN3O/thqSs2L+ggGAmx4dtwd61CI+h0g2NQoIPK
bPuARaMWNL8Sxn6uzL31lP/I34ihl/IM9Uy/mFp0btrqAQJdhA251W2qO/VFktjj
GgNy0MvuefdPYImpcSaHeoPouDo+u9pW7EcRMY4xe2wFa3R+xoNl/5NzQbKEYAgp
rZx3VwygsNBuD5sGQ2XELgCaz05YQV+Eb4T6+fdyZDzGl4A5QChv3oRCWnyesT3q
ufMZM5SmaubxajBaASlOcLLMZc1uJIzEYStIlmdGBGyXq0Ekk6saOYrjnhep4p+f
5sYMQ54RhwCS8quP1EI9oTUopl3RNbHCE8E7NHGvPQBFdktj3GgEgiJN6APaXXbO
Hp0KfeD9J9eHFHd14N8H96ZN20pL463sy+FIhXXSuZ7/GqMO8asBGLXrhU/CJ5fp
2s/HNA/iwsk+TZE6LGf30KBfGsB5ChcmTrrbleil69B1X/CoLZy3oamay7fh2fcv
AwULsirCWe97Mop27fjjG+j9906O/jbFjbEVhMLYmZ73fL1tLq5dgkU1SW5C6ikM
HUgBM5hT5L7Vc+V9fcCKVEmC/hyDCYiFZWnArJSxZumyfN0xWcXQj93NkBuXDFL7
H6BpMqr0LwRvl3uOLMu49/xzXSx3g067GL0KVTuz8/Pfx2x6PeAObuRWsVo9mGW+
StkUYhfba2+l9f24U503kpHd8IaVBEGYG9rOVzcNETsceUgS6xnyrT5m/YroZWkm
CheZsdWxpvTngagdyndABuekGvkA7/PiLsyUdeUpgojgbpoL2kRFLkh/xT0UaTIA
h3OyBqLtw0kak2l8x4u5+KIMex/tPk3T3JgTknrL4KFnHpzNuy03hqdCY0ECNHXP
8j9AbwXkvYWffmFYu7qrMWN2fm/bhqBe19+1wflMiMs69hlBVdYBbDjK1bDDQCs2
hmM2rud6oMY7aI61165qvJxTCNGttLaW0VAGO1ZPlgoqiuGtFEIsohpM+DRzjWg6
PZidbAAwDTzl222a/Bmq4yWmR1PxZTecjs/mjnWH+TsVOJX/tBZ5L3WbpcNEUWH5
6hg3+/wYdOZYRYh4QBvG0tk/ABar9Q5cUwnNpFgfrZu3xs4wfJUXR4xVVk8Oycin
3WokdAXBO5i2xBs5EUh9uKL5GZPBTOQI6u6br6maZC1DRaRv58pKp5729msig7qP
QyUxtxEtg6I86q7UkwD8uanxv0Q+04GIF+BSsj2oDRneKixWiTBvCZKMV6KYWp2p
SgdALK9CuBixDAFT1ItAgoBTjbfPh6fAHbBEj5JGLgfs08WQGGng7dXwn8JgpuXL
T8tDayW44xXlLXNs8qoDFAdfC5XRw2EhBEovndbW+0yNtgCVBg4s5ezTBYrBm1Wq
Pj3XnhNtJMKEMN5rwP2QkCy0olBcJg79V7WYR6nXunkY0SrzToJd/uCSvOedRapE
EU+Ahg+Y7JvKfsZ273wkVaKHmxAbPcUdYR8dxo6yQyPh6voAlLXGTK4ODCLupGJb
u7NHigvstDCuwuwfwyg=
-----END ENCRYPTED PRIVATE KEY-----
`

const encryptedRSA2048pbeMd5Des = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIQPjEZXcFaqoCAggABIIEyEmYccMBg2q+7VYn
Bu3oRqkgKCmvzKl4sHVtEPqyDRq8uSo6va0u5qRVn1AG2vGYCdwnFUGChF26jUaB
RIKBLMnOKlaCm1CQaXjWMWTvHY85vUe/NFNgMn/V6bl1PkyvQ6OeIEQ1Y8eUiN90
fO4nSSdNFlLSvBsZdjz4kh7GPNJk6QG27fr3tvta9XG3ikLf5HWvrxNAgzIYHMxh
xamwcOucxqasEwj++KvFqzfLBP93CXCAgTDHN0tAg/hxgVOzXMepWcmzM1zMxp3I
OuqHaxXY1Rg8A/iP2tDHpDxOSI57qkYmX7D+RfxMWKSWo3ZfwbK9xR1hcgg1s43d
gHkzBSUkDicVdqNBP9Bc9lbdu72s8IvCI0mS8BxnVml7kSFpWSO/owmcK7E9FY4T
VAXb7trHQZtA2i6eieTPXeidaUZZFgZZv5mVDScxxQYzjC6e+Vfu8dIkgYCZjpqE
EEPHJ/WktLZR1RckRzvGqafsCRT0Sp68nWaTj/Rp8mx8ZmmuZ5u4L4WtzBUZWWX2
Hhpox42EZ9GBsLGMpv+32AmU04pL3V0QCfFiFm6muUt2iEu6QIzyWj3iVqGBIHNy
ngNpJThh6WLpAWSSbmqRIrktp7WQpqPuDiPcDjPo81kkpLOuHL6r1Ifrs+95zLGJ
giB/7UpbZDQkytAFQmucexKHeo2fwMbxsaAg5hQpJ4MFYFTLAYlrH2oppw3qAqLb
WUzNdOLyU0Aek3gFvYSTmFLzWyTg8tNWwNapPvlMfNrYm9NNpmhB098i+boK5an0
CBbupZzlPlsAV3iQdZxrYCB0umy/wpNVAgQNaX3qFWaI4Fl6ZA47YM50Ehl6/v+K
J7hpM3gIBMBMCm08LcaGF0IOOtB8H11g7hUCm8l7MJGrbrPZ3+ewXd20llzIIP5U
QxPsqZq/bmCcDwi1SJDbpCU47sJxDBfCzMlECsTFCyL0uv5m8hGQQ1QKSUV0TGpu
7p/WCdBZAHHXfZHisHT5RfQQhe6ECJLfVxvEPhSGYeKwM1YEeDUMG8razwQgs3dc
xVsmIpX3knnzM89xvPLrYSCkn63VajIpaxQrtj2yKbPC+yKYvFgEmKLRPhxrg0jw
YSJW18DUCFGE8O2ZnQEKdVa60B0xiSR5cnZCFBZZNO7qobN3G/TdNv1BFWezF9gT
iPxwIbZDRkHK6LO5rRxrTieOtSpr0I3zJDUg6D4C1E+kaY5mlcRnLnW4fUeN8Wjc
r7gpJrAKuU/9OZgErB7/lmAl96kAW3frKyAOdE8T6cp5TCPRdqxsY+DWxSjU4/iH
ZFSCXxRzzstKnDDRk1NvcfiLwE0BOmhgmCnvn2uRmXi/sWP5lHKxqj4b5xE3NYFw
sS/1Uwz4YjvfE/jMdjxImpBkH376iOHQqyZyQ7OuKy5IMk2YHQNUKfzM37ejBYpO
pumHmkG/1tYKAvLI/WDaQLAtmWTVIJBnJKUGlfY0j9SuGxgjZwUOfuepLcCtfyD1
Q+J2KQSVw47DTAYiLVrYEZhgKVAVSNmQlBU4M/MCe2f4FdmxBVFdENgRCwed+7gI
vc8yo8Vha6id0d0bM/5WTjcz3IDhkSdp+uaD0QwCKMDRJXnW4K3RjzcCDdJI89Gq
twrS8jv8K//nip1bkw==
-----END ENCRYPTED PRIVATE KEY-----
`

const ec256 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjLFzKb/8hsdSmPft
s98RZ7AWzQnLDsMhy6v+/3BZlZ6hRANCAASKkodoH+hHmBfwoFfrvv1E+iMLt3g1
s6hxOUMbkv6ZTVFXND/3z9zlJli6/YGrlSnsHOJc0GbwSYD1AMwZyr0T
-----END PRIVATE KEY-----
`

const encryptedEC256aes = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjVvKZtHlmIbAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEL3jdkBvObn+QELgKVE2cnMEgZAl
wgo3AjtXevJaGgep5GsW2krw9S7dC7xG9dR33Z/a9nBnO1rKm7Htf0+986w/1vmj
4k3M2QiI/VY+tnDFE+46DLLKYtJGRT1aoAH+mwhzaQGwzJnKhbeA23aE0f7KWCAK
+f999+SeHWro7FiRZjHEYVVLGQr/I7K5Wyh24YjN2nR4CU4X+GQU25My/pgSRog=
-----END ENCRYPTED PRIVATE KEY-----
`

const ec128 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjLFzKb/8hsdSmPft
s98RZ7AWzQnLDsMhy6v+/3BZlZ6hRANCAASKkodoH+hHmBfwoFfrvv1E+iMLt3g1
s6hxOUMbkv6ZTVFXND/3z9zlJli6/YGrlSnsHOJc0GbwSYD1AMwZyr0T
-----END PRIVATE KEY-----`

const encryptedEC128aes = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAg7qE4RYQEEugICCAAw
HQYJYIZIAWUDBAECBBBa+6eKv6il/iEjOw8/AmEHBIGQ24YmBiMfzjJjFU+PAwXr
zCfR3NPOHBwn3+BkpyivaezSrFWIF919cnDyI15Omd+Iz2oljrT/R4IDC9NOmoAy
5uKixYGAOi74Qr9kdgrT2Bfvu9wq+dYqPwLjR4WFHl2ofrLn7RCaOa8mOh3bgfHP
SnXPiACchx53PDh6bZTIZ0V9v0ymcMuXf758OXbUmSGN
-----END ENCRYPTED PRIVATE KEY-----`

const encryptedEC256aes128sha1 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAgEoFG3x07DbQICCAAw
HQYJYIZIAWUDBAECBBCRN9PNX9rBqXhaHLUOsv7YBIGQFfXAPPV+COWABJdSarog
eUHFNaQ+R6x55Tz/mquNIwiOrP9DNoEd1PGtKaHaO+ACSEQwMfrGeh8BuNV69EwP
bhsob/MZeexRbrLe2YN7Y7/Y0wpujalGlliMvs35f1fpq/9RfVU+qRpFED2lT4dm
zOuhMC9Oo3oMYlbEXAT9mq33MkGKMUth2ek/bQIvnCHG
-----END ENCRYPTED PRIVATE KEY-----
`

// From https://tools.ietf.org/html/rfc7914
const encryptedRFCscrypt = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI
AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy
+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL
iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z
+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg==
-----END ENCRYPTED PRIVATE KEY-----
`

func TestParsePKCS8PrivateKeyRSA(t *testing.T) {
	keyList := []struct {
		name      string
		clear     string
		encrypted string
	}{
		{
			name:      "encryptedRSA2048aes",
			clear:     rsa2048,
			encrypted: encryptedRSA2048aes,
		},
		{
			name:      "encryptedRSA2048des3",
			clear:     rsa2048,
			encrypted: encryptedRSA2048des3,
		},
		{
			name:      "encryptedRSA512PbeWithMD5AndDESCBC",
			clear:     rsa2048,
			encrypted: encryptedRSA2048pbeMd5Des,
		},
		{
			name:      "encryptedRSA2048pbeSha3Des",
			clear:     rsa2048,
			encrypted: encryptedRSA2048pbeSha3Des,
		},
	}
	for i, key := range keyList {
		i := i
		key := key
		t.Run(key.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(key.encrypted))
			_, err := pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, []byte("password"))
			if err != nil {
				t.Errorf("%d: ParsePKCS8PrivateKeyRSA returned: %s", i, err)
			}
			_, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, []byte("wrong password"))
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}
			_, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes)
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}

			block, _ = pem.Decode([]byte(key.clear))
			_, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes)
			if err != nil {
				t.Errorf("%d: ParsePKCS8PrivateKeyRSA returned: %s", i, err)
			}
		})
	}
}

func TestParsePKCS8PrivateKeyECDSA(t *testing.T) {
	keyList := []struct {
		name      string
		clear     string
		encrypted string
	}{
		{
			name:      "encryptedEC256aes",
			clear:     ec256,
			encrypted: encryptedEC256aes,
		},
	}
	for i, key := range keyList {
		i := i
		key := key
		t.Run(key.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(key.encrypted))
			_, err := pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes, []byte("password"))
			if err != nil {
				t.Errorf("%d: ParsePKCS8PrivateKeyECDSA returned: %s", i, err)
			}
			_, err = pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes, []byte("wrong password"))
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}
			_, err = pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes)
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}

			block, _ = pem.Decode([]byte(key.clear))
			_, err = pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes)
			if err != nil {
				t.Errorf("%d: ParsePKCS8PrivateKeyECDSA returned: %s", i, err)
			}
		})
	}
}

func TestParsePKCS8PrivateKey(t *testing.T) {
	keyList := []struct {
		name      string
		clear     string
		encrypted string
		password  string
	}{
		{
			name:      "encryptedRSA2048aes",
			clear:     rsa2048,
			encrypted: encryptedRSA2048aes,
			password:  "password",
		},
		{
			name:      "encryptedRSA2048des3",
			clear:     rsa2048,
			encrypted: encryptedRSA2048des3,
			password:  "password",
		},
		{
			name:      "encryptedRSA2048scrypt",
			clear:     rsa2048,
			encrypted: encryptedRSA2048scrypt,
			password:  "password",
		},
		{
			name:      "encryptedEC256aes",
			clear:     ec256,
			encrypted: encryptedEC256aes,
			password:  "password",
		},
		{
			name:      "encryptedEC256aes128sha1",
			clear:     ec256,
			encrypted: encryptedEC256aes128sha1,
			password:  "password",
		},
		{
			name:      "encryptedRFCscrypt",
			clear:     "",
			encrypted: encryptedRFCscrypt,
			password:  "Rabbit",
		},
		{
			name:      "encryptedEC128aes",
			clear:     ec128,
			encrypted: encryptedEC128aes,
			password:  "password",
		},
	}
	for i, key := range keyList {
		i := i
		key := key
		t.Run(key.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(key.encrypted))
			_, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(key.password))
			if err != nil {
				t.Errorf("%d: ParsePKCS8PrivateKey returned: %s", i, err)
			}
			_, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte("wrong password"))
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}
			_, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				t.Errorf("%d: should have failed", i)
			}

			if key.clear != "" {
				block, _ = pem.Decode([]byte(key.clear))
				_, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					t.Errorf("%d: ParsePKCS8PrivateKey returned: %s", i, err)
				}
			}
		})
	}
}

func TestConvertPrivateKeyToPKCS8(t *testing.T) {
	for i, password := range [][]byte{nil, []byte("password")} {
		var args [][]byte
		if password != nil {
			args = append(args, password)
		}
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("%d: GenerateKey returned: %s", i, err)
		}
		der, err := pkcs8.ConvertPrivateKeyToPKCS8(rsaPrivateKey, args...)
		if err != nil {
			t.Fatalf("%d: ConvertPrivateKeyToPKCS8 returned: %s", i, err)
		}
		decodedRSAPrivateKey, err := pkcs8.ParsePKCS8PrivateKey(der, args...)
		if err != nil {
			t.Fatalf("%d: ParsePKCS8PrivateKey returned: %s", i, err)
		}
		if rsaPrivateKey.D.Cmp(decodedRSAPrivateKey.(*rsa.PrivateKey).D) != 0 {
			t.Fatalf("%d: Decoded key does not match original key", i)
		}

		for _, curve := range []elliptic.Curve{
			elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521(),
		} {
			ecPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("%d, %s: GenerateKey returned: %s", i, curve, err)
			}
			der, err = pkcs8.ConvertPrivateKeyToPKCS8(ecPrivateKey, args...)
			if err != nil {
				t.Fatalf("%d, %s: ConvertPrivateKeyToPKCS8 returned: %s", i, curve, err)
			}
			decodedECPrivateKey, err := pkcs8.ParsePKCS8PrivateKey(der, args...)
			if err != nil {
				t.Fatalf("%d, %s: ParsePKCS8PrivateKey returned: %s", i, curve, err)
			}
			if ecPrivateKey.D.Cmp(decodedECPrivateKey.(*ecdsa.PrivateKey).D) != 0 {
				t.Fatalf("%d, %s: Decoded key does not match original key", i, curve)
			}
		}
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	for i, tt := range []struct {
		password []byte
		opts     *pkcs8.Opts
	}{
		{
			password: nil,
			opts:     nil,
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES128CBC,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 8, IterationCount: 2048, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES192CBC,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 8, IterationCount: 1000, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES256CBC,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 16, IterationCount: 2000, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES128GCM,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 8, IterationCount: 2048, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES192GCM,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 8, IterationCount: 10000, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES256GCM,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 16, IterationCount: 16, HMACHash: crypto.SHA256,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.TripleDESCBC,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize: 16, IterationCount: 16, HMACHash: crypto.SHA1,
				},
			},
		},
		{
			password: []byte("password"),
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES256CBC,
				KDFOpts: pkcs8.ScryptOpts{
					CostParameter:            1 << 2,
					BlockSize:                8,
					ParallelizationParameter: 1,
					SaltSize:                 16,
				},
			},
		},
	} {
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("%d: GenerateKey returned: %s", i, err)
		}
		der, err := pkcs8.MarshalPrivateKey(rsaPrivateKey, tt.password, tt.opts)
		if err != nil {
			t.Fatalf("%d: MarshalPrivateKey returned: %s", i, err)
		}
		decodedRSAPrivateKey, _, err := pkcs8.ParsePrivateKey(der, tt.password)
		if err != nil {
			t.Fatalf("%d: ParsePKCS8PrivateKey returned: %s", i, err)
		}
		if rsaPrivateKey.D.Cmp(decodedRSAPrivateKey.(*rsa.PrivateKey).D) != 0 {
			t.Fatalf("%d: Decoded key does not match original key", i)
		}

		for _, curve := range []elliptic.Curve{
			elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521(),
		} {
			ecPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("%d, %s: ConvertPrivateKeyToPKCS8 returned: %s", i, curve, err)
			}
			der, err = pkcs8.MarshalPrivateKey(ecPrivateKey, tt.password, tt.opts)
			if err != nil {
				t.Fatalf("%d, %s: ConvertPrivateKeyToPKCS8 returned: %s", i, curve, err)
			}
			decodedECPrivateKey, _, err := pkcs8.ParsePrivateKey(der, tt.password)
			if err != nil {
				t.Fatalf("%d, %s: ParsePKCS8PrivateKey returned: %s", i, curve, err)
			}
			if ecPrivateKey.D.Cmp(decodedECPrivateKey.(*ecdsa.PrivateKey).D) != 0 {
				t.Fatalf("%d, %s: Decoded key does not match original key", i, curve)
			}
		}
	}
}

type unknown int

func TestUnknownTypeFailure(t *testing.T) {
	badInput := unknown(0)
	_, err := pkcs8.ConvertPrivateKeyToPKCS8(badInput, []byte("password"))
	if err == nil {
		t.Fatal("expected error")
	}
}
