# OMTG-Android - 01. Bad Encryption - Solution

> MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."

**Summary of the challenge:** Identify the password by reading the source code and decrypt the hardcoded secret.

<br/>First, install the vulnerable OMTG mobile application to an Android test device using [Android Debug Bridge](https://developer.android.com/studio/command-line/adb):

```
C:\>adb install app-arm-debug-Android5.apk
Performing Push Install
app-arm-debug-Android5.apk: 1 file pushed. 4.1 MB/s (5810897 bytes in 1.344s)
        pkg: /data/local/tmp/app-arm-debug-Android5.apk
Success
```

Then, open the APK file using [JADX-GUI](https://github.com/skylot/jadx) tool to obtain the Java source code. This tool can decompile Dalvik bytecode to Java classes straight from APK. Find the relevant class and method which handles the password validation.

![git-01](https://user-images.githubusercontent.com/55597077/65349322-07ff3f80-dbdb-11e9-8d40-b7ce5658e400.png)
<br/>
<br/>
The `verify(String str)` method is reponsible for the password verification, which can be found under the `sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_BadEncryption` class:

```java
public static boolean verify(String str) {
        byte[] encryptedDecoded = Base64.decode("vJqfip28ioydips=", 0);
        byte[] userPass = encrypt(str);
        if (userPass.length != encryptedDecoded.length) {
            return false;
        }
        for (int i = 0; i < userPass.length; i++) {
            if (userPass[i] != encryptedDecoded[i]) {
                return false;
            }
        }
        return true;
    }
```

Despite of the hardcoded password is a Base64 string, it is not possible to reveal the plain-text format, since the original secret was encrypted by the following method:

```java
 private static byte[] encrypt(String str) {
        byte[] bytes = str.getBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ Ascii.DLE);
            bytes[i] = (byte) ((bytes[i] ^ -1) & 255);
        }
        return bytes;
    }
```

After, the user submits the password, the `encrypt` method is called to perform the encryption. Each character of the byte array containing the user's input, then this will be changed by bitwise XOR and bitwise AND operators through a for loop. 

The XOR logical operator denoted by `^` sign and returns bit by bit XOR of input values, so if corresponding bits are different it gives 1, else it gives 0. Take an example below:
```
1110100 (binary input 1)
0010000 (binary input 2)
-------
1100100 (binary result)
```
The AND logical operator denoted by `&` sign and returns bit by bit AND of input values, so if both bits are 1, it gives 1, else it gives 0. Take an example below:
```
00000000000000000000000001110100 (binary input 1)
11111111111111111111111111111111 (binary input 2)
--------------------------------
11111111111111111111111110001011 (binary result)
```

There is a variable called `Ascii.DLE` which needs to be clarified before we move on. The value of this variable is `16` and it can be found in the [Guava: Google Core Libraries](https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Ascii.java) source code.
```java
public static final byte DLE = 16;
```
<br/>

Now everything is known to create a simple [Python](https://www.python.org/download/releases/3.0/) script for the password decyption. We need the encrypted secret from the Java source code then, assign this base64 value to the `base64password` variable, after handle the decoded value as a byte array. Iterate through the array and manage to modify the characters by the XOR, AND operators in reverse order.

```python
import base64

base64password = 'vJqfip28ioydips='
encoded = bytearray(base64.b64decode(base64password))
for i in range(len(encoded)):
	encoded[i] = (encoded[i] ^ -1) & 255
	encoded[i] = encoded[i] ^ 16

print(encoded.decode())
```

Execute the Python script to reveal the password:

<img src="https://user-images.githubusercontent.com/55597077/65354427-66cab600-dbe7-11e9-8b5a-786f06c265d2.png">

The challenge is solved:

<img src="https://user-images.githubusercontent.com/55597077/65355265-78ad5880-dbe9-11e9-921b-e94ebdb5e60c.png" width="377">
