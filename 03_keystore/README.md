# OMTG-Android - 03. KeyStore - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."

**Summary of the challenge:** [Android Keystore](https://developer.android.com/training/articles/keystore.html) system provides a secure container to store cryptographic keys or other sensitive information. This challenge demonstrates a proper implementation of Android Keystore usage which mitigates unauthorized use of key material outside of the device by preventing private key extraction.

The Keystore system may involve TEE (Trusted Execution Environment, e.g. ARM TrustZone Technology) hardware based secure storage. This feature is necessary to be supported by the manufacturer of the device. In case of TEE is not supported, software based implementation of the Keystore system is available. Remember that Android Keystore interacts with the Keymaster in TEE through the Keystore service, where the Keymaster is responsible for the cryptographic operations.

The following code snippet creates a key and stores it inside the Android Keystore System. The process begins with grabbing an instance of Android Keystore, then looks up the alias called `Dummy` to create the RSA public and private key pair. The Android Keystore provider feature was introduced in Android 4.3 (API level 18).
```java
public void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  try {
    this.keyStore = KeyStore.getInstance("AndroidKeyStore");
    this.keyStore.load(null); 
  } 
  [...]
  createNewKeys();
}

public void createNewKeys() {
  String alias = "Dummy";
  try {
    if (!this.keyStore.containsAlias(alias)) {
      Calendar start = Calendar.getInstance();
      Calendar end = Calendar.getInstance();
      end.add(1, 1);
      KeyPairGeneratorSpec spec = null;
      if (VERSION.SDK_INT >= 18) {
        spec = new Builder(this).setAlias(alias).setSubject(new X500Principal("CN=Sample Name, O=Android Authority")).setSerialNumber(BigInteger.ONE).setStartDate(start.getTime()).setEndDate(end.getTime()).build();
      }
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
      generator.initialize(spec);
      KeyPair generateKeyPair = generator.generateKeyPair();
      Toast.makeText(getApplicationContext(), "Key Pair \"Dummy\" created.", 1).show();
      return;
    } [...]
} }
```

The generated keypair is stored in files within the `/data/misc/keystore/user_0` directory. These files are encrypted using a device-specific key in the TEE, their names are correlated with the app ID and the alias defined by the application developer.
```bash
shell@osprey_umts:/data/misc/keystore/user_0 # ls -la
-rw------- keystore keystore       84 2019-09-23 18:53 .masterkey
-rw------- keystore keystore      788 2019-09-23 19:20 10120_USRCERT_Dummy
-rw------- keystore keystore     1652 2019-09-23 19:20 10120_USRPKEY_Dummy
```

After the key pair has been created, the public key can be used for data encryption and the private key for decryption. These methods are fundamentally identical except the encryption mode.
```java
public void encryptString(String alias) {
  try {
    RSAPublicKey publicKey = (RSAPublicKey) ((PrivateKeyEntry) this.keyStore.getEntry(alias, null)).getCertificate().getPublicKey();
    [...]
    Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
    inCipher.init(1, publicKey);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inCipher);
    cipherOutputStream.write(initialText.getBytes(StringEncodings.UTF8));
    cipherOutputStream.close();
    byte[] vals = outputStream.toByteArray();
    [...]
}

public void decryptString(String alias) {
  try {
    PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) this.keyStore.getEntry(alias, null);
    RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
    [...]
    Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
    output.init(2, privateKey);
    CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(Base64.decode(this.encryptedText.getText().toString(), 0)), output);
    ArrayList<Byte> values = new ArrayList<>();
    [...]
}
```

From Android 6.0 (Marshmallow) the `AndroidOpenSSL` should not be used for cipher creation, it would fail with `Need RSA private or public key` at cipher init for decryption. This issue is resolved in the `app-arm-debug.apk` build by the `Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");` declaration.

Here is the implemented code for Android 6.0 and above:
```java
public void decryptString(String alias) {
  try {
    PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) this.keyStore.getEntry(alias, null);
    Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    output.init(2, privateKeyEntry.getPrivateKey());
    [...]
} }
```

The most effective way to inspect the methods of a mobile application is the dynamic analysis using [Frida framework](https://www.frida.re/). Frida is a dynamic code instrumentation toolkit which allows injection of JavaScript snippets into  apps on Android, iOS, macOS, Windows, GNU/Linux, and QNX. Frida's core is written in C and injects [Google's V8 engine](https://v8.dev/) into the target process, where the JavaScript code gets executed with full access to memory to hook functions and call native functions inside the process through a two-way communication channel.

First, download the latest version of [frida-server for Android](https://github.com/frida/frida/releases), copy the binary to the test devie, change the persmissions and launch the server:
```bash
C:\>adb push frida-server /data/local/tmp/
C:\>adb shell
shell@osprey_umts:/ $ su
shell@osprey_umts:/ # chmod 755 /data/local/tmp/frida-server
shell@osprey_umts:/ # /data/local/tmp/frida-server &
[1] 27938
shell@osprey_umts:/ # 
```

Then install Frida client on Windows, Linux or macOS. Note that Python and pip are pre-requirements.
```bash
C:\>pip install frida
Collecting frida
Installing collected packages: frida
```

By analysing the application, it turns out the `init` method of the `Cipher` object can provide access to the `RSAPublicKey` and `RSAPrivateKey` interfaces and so the keys. The `init` method has two input parameters, the operation mode (where value `1` means ENCRYPT_MODE, value `2` means DECRYPT_MODE) and the key to initialize the cipher with the provided key.
```java
public void encryptString(String alias) {
  [...]
  Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
  inCipher.init(1, publicKey);
  [...]
}

public void decryptString(String alias) {
  [...]
  Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
  output.init(2, privateKey);
  [...]
}
```

The RSA public and private keys are inherited from the `java.security.interfaces.RSAPublicKey` and `java.security.interfaces.RSAPrivateKey` classes. Relevant code snippet of the application:
```java
RSAPublicKey publicKey = (RSAPublicKey) ((PrivateKeyEntry) this.keyStore.getEntry(alias, null)).getCertificate().getPublicKey();
[...]
RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
```

Create the following Frida script called `keystore.js` to obtain the RSA public key in Base64 format, as well as its exponent and modulus components. The key parameter of the `init` method has to be casted two times. Once by the [RSAPublicKey](https://developer.android.com/reference/java/security/interfaces/RSAPublicKey) interface to access the public key exponent, second time by the [RSAKey](https://developer.android.com/reference/java/security/interfaces/RSAKey) to read the modulus.
```javascript
Java.perform(function(){
  var Cipher = Java.use("javax.crypto.Cipher"); //load the Cipher class into a variable to access the init method
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){ //hook the init method
    if (opmode == 1) //encrypt opmode
    {
      var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey"); //load the RSA interfaces into variables
      var RSAKey = Java.use("java.security.interfaces.RSAKey");
      var casted_RSAPublicKey = Java.cast(key, RSAPublicKey);  //cast the key to obtain the public key and the exponent
      var casted_RSAKey = Java.cast(key, RSAKey); //cast the key to obtain the modulus
      var base64 = Java.use("android.util.Base64"); //load base64 class to encode byte array to base64 string
      console.log("[*] Method 'init' is called with ENCRYPT_MODE opcode");
      console.log("[*] Public key in Base64 format: " +  base64.encodeToString(key.getEncoded(), 0));
      console.log("[*] Exponent of the public key: " + casted_RSAPublicKey.getPublicExponent());
      console.log("[*] Modulus of the public key: " + casted_RSAKey.getModulus());
    }
    return this.init(opmode, key);
  }
});
```

Now everything is ready to start hooking the application. Open the app first on thed device, then attach the Frida client to the application's process with the following command:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l keystore.js --no-pause
```

Type a secret into the `Clear Text` field and tap on `Encrypt` button.

<img src="https://user-images.githubusercontent.com/55597077/65553970-1f626380-df20-11e9-8715-772889f793b2.png" width="377">
<img src="https://user-images.githubusercontent.com/55597077/65553971-1f626380-df20-11e9-8f98-0f22ceb51ca5.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l keystore.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> 
[*] Method 'init' is called with ENCRYPT_MODE opcode
[*] Public key in Base64 format: 
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHd6Cs3B8vLiwlq4GAoxkhUL9mMWrWBi
NtbANuMwF8LfuALiYLvD4nUtECbVyGqe1XWxFNg5bV2pJeapTDeaQy7q/+YtCZ0msU1iBUtUu522
nZos8vS/Br63DKnOxS1DntzYAswuQJJAt6/5rxFB8PQy3sri9ZQKtUMUFY7KtCHb1CdKG594h33n
Nz+KxyJxwtKFM/h/zaM6brDUAEmH4DhEUjlY8L5zJXaff8bpC90v9uAXS0Q5n2G/2qq9jGGYusxh
kMc4oe6Cv3/rwncPZcIwthSJT9wdeSIUadhVVtXiHMxEnaz2dQE2vK4CHIJmK+u/tppVVn6M8XHc
a69h4QIDAQAB
[*] Exponent of the public key: 65537
[*] Modulus of the public key: 24296670723576257130124475223772461813086944258848982453429486035533885875282890192076417507196006357703118170305640200904218722930443416442857969285081288220573971037926894684967145417095184862782936029298512954858273013481789241294793080321807104858949313838533672103895770411425260625466894302074176704003306519008165410105611373564028714862857589437352289550522505477025270762090809970964824251727369058077170995930987146799919537110988471330458725905820905418813244729836453728345255475918692511400006770889580359038376891646744124411325512763177749868256680193632230984965074258683400884271453232923392273768929
```

RSA key format is defined according to the [RFC 3447](https://www.ietf.org/rfc/rfc3447.txt) and [RFC 5280](https://www.ietf.org/rfc/rfc5280.txt) standards based on ASN.1 and includes the 2048-bit Modulus and the public Exponent, which is usually chosen as either 3 or 65537. 

Alternative process to convert the base64 formatted certificate to Modulus and Exponent using OpenSSL:
```bash
root@host:~# echo MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHd6Cs3B8vLiwlq4GAoxkhUL9mMWrWBiNtbANuMwF8LfuALiYLvD4nUtECbVyGqe1XWxFNg5bV2pJeapTDeaQy7q/+YtCZ0msU1iBUtUu522nZos8vS/Br63DKnOxS1DntzYAswuQJJAt6/5rxFB8PQy3sri9ZQKtUMUFY7KtCHb1CdKG594h33nNz+KxyJxwtKFM/h/zaM6brDUAEmH4DhEUjlY8L5zJXaff8bpC90v9uAXS0Q5n2G/2qq9jGGYusxhkMc4oe6Cv3/rwncPZcIwthSJT9wdeSIUadhVVtXiHMxEnaz2dQE2vK4CHIJmK+u/tppVVn6M8XHca69h4QIDAQAB | base64 -d | openssl rsa -pubin -inform DER -text -noout -modulus
RSA Public-Key: (2048 bit)
[...]
Exponent: 65537 (0x10001)
Modulus=C0777A0ACDC1F2F2E2C25AB8180A3192150BF66316AD606236D6C036E33017C2DFB802E260BBC3E2752D1026D5C86A9ED575B114D8396D5DA925E6A94C379A432EEAFFE62D099D26B14D62054B54BB9DB69D9A2CF2F4BF06BEB70CA9CEC52D439EDCD802CC2E409240B7AFF9AF1141F0F432DECAE2F5940AB54314158ECAB421DBD4274A1B9F78877DE7373F8AC72271C2D28533F87FCDA33A6EB0D4004987E03844523958F0BE7325769F7FC6E90BDD2FF6E0174B44399F61BFDAAABD8C6198BACC6190C738A1EE82BF7FEBC2770F65C230B614894FDC1D79221469D85556D5E21CCC449DACF6750136BCAE021C82662BEBBFB69A55567E8CF171DC6BAF61E1
```

Convert the hexadecimal Modulus to decimal format:
```bash
root@host:~# echo 'ibase=16;C0777A0ACDC1F2F2E2C25AB8180A3192150BF66316AD606236D6C036E33017C2DFB802E260BBC3E2752D1026D5C86A9ED575B114D8396D5DA925E6A94C379A432EEAFFE62D099D26B14D62054B54BB9DB69D9A2CF2F4BF06BEB70CA9CEC52D439EDCD802CC2E409240B7AFF9AF1141F0F432DECAE2F5940AB54314158ECAB421DBD4274A1B9F78877DE7373F8AC72271C2D28533F87FCDA33A6EB0D4004987E03844523958F0BE7325769F7FC6E90BDD2FF6E0174B44399F61BFDAAABD8C6198BACC6190C738A1EE82BF7FEBC2770F65C230B614894FDC1D79221469D85556D5E21CCC449DACF6750136BCAE021C82662BEBBFB69A55567E8CF171DC6BAF61E1' | bc
24296670723576257130124475223772461813086944258848982453429486035533885875282890192076417507196006357703118170305640200904218722930443416442857969285081288220573971037926894684967145417095184862782936029298512954858273013481789241294793080321807104858949313838533672103895770411425260625466894302074176704003306519008165410105611373564028714862857589437352289550522505477025270762090809970964824251727369058077170995930987146799919537110988471330458725905820905418813244729836453728345255475918692511400006770889580359038376891646744124411325512763177749868256680193632230984965074258683400884271453232923392273768929
```

During the decryption process, the [Cipher](https://developer.android.com/reference/javax/crypto/Cipher) object is using the `AndroidOpenSSL` cryptographic provider which prevents the private exponent to be exported from the device.
```java
Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
```

The `AndroidOpenSSL`provider uses the [OpenSSLRSAPrivateKey](https://android.googlesource.com/platform/libcore/+/android-4.4.2_r1/crypto/src/main/java/org/conscrypt/OpenSSLRSAPrivateKey.java) class to load and cast the `RSAPrivateKey` interface to `OpenSSLRSAPrivateKey`.
```java
@Override
public final BigInteger getPrivateExponent() {
  if (key.isEngineBased()) {
    throw new UnsupportedOperationException("private exponent cannot be extracted");
  }
  ensureReadParams();
  return privateExponent;
}
```

Accordingly, this is the final Frida script to export the RSA key pairs:
```javascript
Java.perform(function(){
  var Cipher = Java.use("javax.crypto.Cipher"); //load the Cipher class into a variable to access the init method
  Cipher.init.overload('int', 'java.security.Key').implementation  = function(opmode, key){ //hook the init method
    
  if (opmode == 1) //encrypt opmode
  {
    var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey"); //load the RSA interfaces into variables
    var RSAKey = Java.use("java.security.interfaces.RSAKey");
    var casted_RSAPublicKey = Java.cast(key, RSAPublicKey);  //cast the key to obtain the public key and the exponent
    var casted_RSAKey = Java.cast(key, RSAKey); //cast the key to obtain the modulus
    var base64 = Java.use("android.util.Base64"); //load base64 class to encode byte array to base64 string
      
    console.log("[*] Method 'init' is called with ENCRYPT_MODE opcode");
    console.log("[*] Public key in Base64 format: " +  base64.encodeToString(key.getEncoded(), 0));
    console.log("[*] Exponent of the public key: " + casted_RSAPublicKey.getPublicExponent());
    console.log("[*] Modulus of the public key: " + casted_RSAKey.getModulus());
  }
  if (opmode == 2) //decrypt opmode
  {
    var RSAPrivateKey = Java.use("java.security.interfaces.RSAPrivateKey"); //load the RSA interfaces into variables
    var OpenSSLRSAPrivateKey = Java.use("com.android.org.conscrypt.OpenSSLRSAPrivateKey");
    var OpenSSLKey = Java.use("com.android.org.conscrypt.OpenSSLKey"); //load the OpenSSL private key component
    var casted_RSAPrivateKey = Java.cast(key, OpenSSLRSAPrivateKey); //cast the OpenSSL private key
    var base64 = Java.use("android.util.Base64"); //load base64 class to encode byte array to base64 string
	  
    OpenSSLKey.isEngineBased.overload().implementation  = function(){ //override the private key export prevention
    console.log("[*] Method 'isEngineBased' is called, overriden");
    return false;
  }
    console.log("[*] Method 'init' is called with DECRYPT_MODE opcode");
    try {
      console.log("[*] Private key in Base64 format: " +  base64.encodeToString(casted_RSAPrivateKey.getEncoded(), 0));
      console.log("[*] Exponent of the private key: " + casted_RSAPrivateKey.getPrivateExponent());  
    }
    catch (error){
      console.log("[*] Exception generated during the private key export: " + error.message);
    }
  }
  return this.init(opmode, key);
  }
});
```

Frida console output:
```bash
[Motorola::sg.vp.owasp_mobile.omtg_android]->
[*] Method 'isEngineBased' is called, overriden
[*] Method 'init' is called with DECRYPT_MODE opcode
[*] Method 'isEngineBased' is called, overriden
[*] Private key in Base64 format: 
MIIBJwIBADANBgkqhkiG9w0BAQEFAASCAREwggENAgEAAoIBAQDAd3oKzcHy8uLCWrgYCjGSFQv2
YxatYGI21sA24zAXwt+4AuJgu8PidS0QJtXIap7VdbEU2DltXakl5qlMN5pDLur/5i0JnSaxTWIF
S1S7nbadmizy9L8GvrcMqc7FLUOe3NgCzC5AkkC3r/mvEUHw9DLeyuL1lAq1QxQVjsq0IdvUJ0ob
n3iHfec3P4rHInHC0oUz+H/NozpusNQASYfgOERSOVjwvnMldp9/xukL3S/24BdLRDmfYb/aqr2M
YZi6zGGQxzih7oK/f+vCdw9lwjC2FIlP3B15IhRp2FVW1eIczESdrPZ1ATa8rgIcgmYr67+2mlVW
fozxcdxrr2HhAgMBAAE=
[*] Method 'isEngineBased' is called, overriden
[*] Method 'isEngineBased' is called, overriden
[*] Exception generated during the private key export: java.lang.NullPointerException: privateExponent == null
```

After extracting raw hex ASN.1 data from the RSA private certificate and examining its structure, it turns out that no private exponent is available as it can be also observed by the generated exception above.
```bash
root@host:~# echo MIIBJwIBADANBgkqhkiG9w0BAQEFAASCAREwggENAgEAAoIBAQDAd3oKzcHy8uLCWrgYCjGSFQv2YxatYGI21sA24zAXwt+4AuJgu8PidS0QJtXIap7VdbEU2DltXakl5qlMN5pDLur/5i0JnSaxTWIFS1S7nbadmizy9L8GvrcMqc7FLUOe3NgCzC5AkkC3r/mvEUHw9DLeyuL1lAq1QxQVjsq0IdvUJ0obn3iHfec3P4rHInHC0oUz+H/NozpusNQASYfgOERSOVjwvnMldp9/xukL3S/24BdLRDmfYb/aqr2MYZi6zGGQxzih7oK/f+vCdw9lwjC2FIlP3B15IhRp2FVW1eIczESdrPZ1ATa8rgIcgmYr67+2mlVWfozxcdxrr2HhAgMBAAE= | base64 -d | openssl asn1parse -inform DER
    0:d=0  hl=4 l= 295 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim: INTEGER           :00
    7:d=1  hl=2 l=  13 cons: SEQUENCE          
    9:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   20:d=2  hl=2 l=   0 prim: NULL              
   22:d=1  hl=4 l= 273 prim: OCTET STRING      [HEX DUMP]:3082010D0201000282010100C0777A0ACDC1F2F2E2C25AB8180A3192150BF66316AD606236D6C036E33017C2DFB802E260BBC3E2752D1026D5C86A9ED575B114D8396D5DA925E6A94C379A432EEAFFE62D099D26B14D62054B54BB9DB69D9A2CF2F4BF06BEB70CA9CEC52D439EDCD802CC2E409240B7AFF9AF1141F0F432DECAE2F5940AB54314158ECAB421DBD4274A1B9F78877DE7373F8AC72271C2D28533F87FCDA33A6EB0D4004987E03844523958F0BE7325769F7FC6E90BDD2FF6E0174B44399F61BFDAAABD8C6198BACC6190C738A1EE82BF7FEBC2770F65C230B614894FDC1D79221469D85556D5E21CCC449DACF6750136BCAE021C82662BEBBFB69A55567E8CF171DC6BAF61E10203010001
```
