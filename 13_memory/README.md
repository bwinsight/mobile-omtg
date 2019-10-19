# OMTG-Android - 13. Memory - Solution

> MSTG-STORAGE-10: "The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use."<br />
> MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."

**Summary of the challenge:** The application leaks sensitive information into the device's memory by decrypting an AES-CBC encrypted string. The objective is to identify and read the plaintext secret from the process memory.

Analysing the memory to find a specific data is a difficult task unless there are some already known patterns about the data we are looking for, such as the encrypted string or the symmetric key. From this case, it is reasonable to start the analysis with the source code.

Due to the source code of the application is not obfuscated, it is possible to decompile the APK file using [JADX-GUI](https://github.com/skylot/jadx) to collect some patterns then identify them in the memory:
```java
public class OMTG_DATAST_011_Memory extends AppCompatActivity {
  String TAG = "OMTG_DATAST_011_Memory";
  String plainText;

  public void onCreate(Bundle savedInstanceState) {
    [...]
    decryptString();
  }

  public void decryptString() {
    SecretKeys privateKey = null;
    try {
      privateKey = AesCbcWithIntegrity.keys("4zInk+d4jlQ3m1B1ELctxg==:4aZtzwpbniebvM7yC4/GIa2ZmJpSzqrAFtVk91Rm+Q4=");
    } catch (InvalidKeyException e) {
        e.printStackTrace();
      }
    try {
      this.plainText = AesCbcWithIntegrity.decryptString(new CipherTextIvMac("6WpfZkgKMJsPhHNhWoSpVg==:6/TgUCXrAuAa2lUMPWhx8hHOWjWEHFp3VIsz3Ws37ZU=:C0mWyNQjcf6n7eBSFzmkXqxdu55CjUOIc5qFw02aVIfQ1CI8axsHijTJ9ZW6ZfEE"), privateKey);
    } catch (UnsupportedEncodingException e2) {
        e2.printStackTrace();
      }
      catch (GeneralSecurityException e3) {
        e3.printStackTrace();
      }
   }
}
```

The task is to recover the value of the `plainText` variable from the memory. Better off starting to identify the input parameters of `AesCbcWithIntegrity.keys` and `CipherTextIvMac` methods.

Click on the Memory button in the application to load the sensitive data into the memory:

<img src="https://user-images.githubusercontent.com/55597077/67133930-202ca380-f207-11e9-819d-2553ae3d9dc2.png" width="296">

Then create a memory dump of the application's process using the [fridump](https://github.com/Nightbringer21/fridump) script:
```bash
C:\fridump>python fridump.py -U -s sg.vp.owasp_mobile.omtg_android

        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|

Current Directory: C:\fridump
Output directory is set to: C:\fridump\dump
Creating directory...
Starting Memory dump...
Oops, memory access violation!-------------------------------] 3.84% Complete
[...]
Oops, memory access violation!#------------------------------] 39.45% Complete
Oops, memory access violation!####---------------------------] 46.85% Complete
Oops, memory access violation!############-------------------] 62.19% Complete
Oops, memory access violation!############-------------------] 62.47% Complete
Oops, memory access violation!#############------------------] 63.29% Complete
Progress: [##################################################] 100.0% Complete

Running strings on all files:
Progress: [##################################################] 100.0% Complete

Finished!

C:\fridump>cd dump
C:\fridump\dump>dir
18/10/2019  22:51    <DIR>          .
18/10/2019  22:51    <DIR>          ..
18/10/2019  22:50         2,101,248 0x12c00000_dump.data
18/10/2019  22:50         4,194,304 0x12e01000_dump.data
18/10/2019  22:50        10,207,232 0x705ab000_dump.data
[...]
18/10/2019  22:51           295,537 strings.txt
             264 File(s)    150,278,769 bytes
```

It is possible to find the decrypted secret in the `strings.txt` file near the parameters of the `AesCbcWithIntegrity.keys` and `CipherTextIvMac` methods more easily. This file contains the extracted strings from the memory dump.
```bash
@Y?fff? 
l?f&q? 
4aZtzwpbniebvM7yC4/GIa2ZmJpSzqrAFtVk91Rm+Q4= 
6/TgUCXrAuAa2lUMPWhx8hHOWjWEHFp3VIsz3Ws37ZU= 
4zInk+d4jlQ3m1B1ELctxg== 
6WpfZkgKMJsPhHNhWoSpVg== 
.<%B 
/<%B 
&MHS 
++sA 
[...]
]B*. 
phiep 
pPiep 
U got the decrypted message. Well done. 
`lrt 
x>\p 
x>\p 
x>\p 
x>\p 
```

The recognised secret is `U got the decrypted message. Well done.`

The same goal can be achieved via the following Frida script `13_memory.js` which hooks the `com.tozny.crypto.android.AesCbcWithIntegrity` class and call the `decryptString` method to reveal the secret.
```javascript
Java.perform(function() {
  
  //Java-AES-Crypto is a simple Android class for encrypting & decrypting strings
  var AesCbcWithIntegrity = Java.use("com.tozny.crypto.android.AesCbcWithIntegrity");
  
  //AES CBC decrypt
  //AesCbcWithIntegrity.decryptString(CipherTextIvMac civ, SecretKeys secretKeys)
  AesCbcWithIntegrity.decryptString.overload('com.tozny.crypto.android.AesCbcWithIntegrity$CipherTextIvMac', 'com.tozny.crypto.android.AesCbcWithIntegrity$SecretKeys').implementation = function(civ, secretKeys) {
    console.log("[*] decryptString method is called, with civ: " + civ); //civ: the cipher text, IV, and mac
    console.log("[*] decryptString method is called, with secretKeys: " + secretKeys); //secretKeys: the AES and HMAC keys
    var retval = this.decryptString(civ,secretKeys); //a string derived from the decrypted bytes
    console.log("[*] Decypted string: " + retval);
    return retval;
  };
});
```

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 13_memory.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> [*] decryptString method is called, with civ: 6WpfZkgKMJsPhHNhWoSpVg==:6/TgUCXrAuAa2lUMPWhx8hHOWjWEHFp3VIsz3Ws37ZU=:C0mWyNQjcf6n7eBSFzmkXqxdu55CjUOIc5qFw02aVIfQ1CI8axsHijTJ9ZW6ZfEE
[*] decryptString method is called, with secretKeys: 4zInk+d4jlQ3m1B1ELctxg==:4aZtzwpbniebvM7yC4/GIa2ZmJpSzqrAFtVk91Rm+Q4=
[*] Decypted string: U got the decrypted message. Well done.
```
