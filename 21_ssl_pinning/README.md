# OMTG-Android - 21. SSL Pinning - Solution

> MSTG-NETWORK-1: "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."<br />
> MSTG-NETWORK-3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."

**Summary of the challenge:** The application is trying to access the `example.com` URL over `https` protocol by ensuring that no plain-text communication is used. The application does not accept self-signed server certificates by default. This challenge can demonstrate that [network traffic sent over HTTPS](https://developer.android.com/training/articles/security-ssl) is secure against Man-in-the-Middle attack by using `HttpsURLConnection` or `SSLSocket` (for socket-level communication using TLS) implementation, as long as the attacker's certificate has not been added to the Android device's Trust Store. This place is where certificates from well-known issuers called Certificate Authorities (CAs) are stored to help the applications determine which certificate can be trusted and which should be considered as un-trusted upon HTTPS connection establishment.

Certificate pinning mechanism is implemented in the challenge application, but only the `Organization Name` field of the server's CA certificate is validated, for this reason the pinning function can be bypassed by convincing the users to add self-signed certificate to their devices that makes them vulnerable to Man-in-the-Middle attack.

Due to the source of the application is not obfuscated, the APK file can be decompiled by the use of [JADX-GUI](https://github.com/skylot/jadx) tool to review `X509TrustManager` implementation, what conditions are necessary for establishing a trusted connection with the backend. The certificate pinning is insecure, because it is relying only on the `Organization Name` field to be equal to `PortSwigger`:
```java
public class HardenedX509TrustManager<E> implements X509TrustManager {
  [...]

  public void checkServerTrusted(X509Certificate[] certificates, String authType) throws CertificateException {
    this.standardTrustManager.checkServerTrusted(certificates, authType);
    for (X509Certificate cert : certificates) {
      String issuer_name = cert.getIssuerDN().getName();
      if (issuer_name.indexOf(",O=PortSwigger,") == -1) {
        throw new CertificateException();
      }
        Log.w("Error", issuer_name);
    }
  }
  [...]
}
```

Generate a self-signed certificate providing `PortSwigger_TEST` string in the Organization Name field:
 ```cmd
 Country Name (2 letter code) [AU]:TE
State or Province Name (full name) [Some-State]:TEST
Locality Name (eg, city) []:TEST
Organization Name (eg, company) [Internet Widgits Pty Ltd]:PortSwigger_TEST
Organizational Unit Name (eg, section) []:TEST
Common Name (e.g. server FQDN or YOUR name) []:TEST
Email Address []:TEST
 ```

The Trusted Credentials setting of Android is divided into two sections: User and System. Only System certificate authorities are trusted by default. Install the previously generated certificate in CRT file format to the device as trusted CA. Open Settings application, choose => Security => Credential storage section, Install from SD card => then select the certificate file to add. 

<img src="https://user-images.githubusercontent.com/55597077/67943036-1cb6f600-fbd1-11e9-9ece-ff52b86cdc5e.png" width="296"> <img src="https://user-images.githubusercontent.com/55597077/67943037-1cb6f600-fbd1-11e9-9fec-14d250f3a381.png" width="296">

Certificate details:

<img src="https://user-images.githubusercontent.com/55597077/67943607-458bbb00-fbd2-11e9-811d-47a1654e73e6.png" width="296">

To capture the HTTPS traffic with an interception proxy such as Burp Suite, configure the proxy settings for the Wi-Fi network. Open Android's Settings application => Wi-Fi, to view a list of available networks => long press the name of the connected Wi-Fi network => Modify network => Advanced options => set Proxy option to Manual and provide the proxy server's IP address and port number:

<img src="https://user-images.githubusercontent.com/55597077/67943144-5851c000-fbd1-11e9-95d2-0d1b90f5ac18.png" width="296">

Tap on the SSL Pinning button to initiate a remote connection over HTTPS protocol:

<img src="https://user-images.githubusercontent.com/55597077/67943480-05c4d380-fbd2-11e9-8456-f46d56b2b30a.png" width="296">

Secure connection cannot be established due to the Organization Name field of the self-signed certificate is ` PortSwigger_TEST` which does not match exactly to the desired `PortSwigger` value. The Burp Suite proxy displays information about the unsuccessful connection: `Proxy	The client failed to negotiate an SSL connection to www.example.com:443: Received fatal alert: certificate_unknown`.

Reviewing the application logs using `adb logcat`, the following entry is generated: `W/Error   (18329): 1.2.840.113549.1.9.1=#160454455354,CN=TEST,OU=TEST,O=PortSwigger,L=TEST,ST=TEST,C=TE`


**Note that by default, applications do not communicate through user-installed CA certificates on Android 7.0 or later version.** 


Generate another self-signed certificate, provide `PortSwigger` string in the Organization Name field to match to the expected organization which is pinned in the application's source:
```cmd
Country Name (2 letter code) [AU]:TE
State or Province Name (full name) [Some-State]:TEST
Locality Name (eg, city) []:TEST
Organization Name (eg, company) [Internet Widgits Pty Ltd]:PortSwigger
Organizational Unit Name (eg, section) []:TEST
Common Name (e.g. server FQDN or YOUR name) []:TEST
Email Address []:TEST
```

Install this certificate to the device using the same method it is described above: 

<img src="https://user-images.githubusercontent.com/55597077/67943698-871c6600-fbd2-11e9-9a7f-a2b013e3222b.png" width="296">

Certificate details:

<img src="https://user-images.githubusercontent.com/55597077/67943711-913e6480-fbd2-11e9-991f-3a7508b6b7c5.png" width="296">

Tap on the SSL Pinning button to initiate a remote connection over HTTPS protocol:

<img src="https://user-images.githubusercontent.com/55597077/67943749-aa471580-fbd2-11e9-8566-c4395003ac82.png" width="296">

This time all the HTTPS traffic can be intercepted, monitored and modified by establishing Man-in-the-Middle attack using Burp Suite proxy on the device's network:

<img src="https://user-images.githubusercontent.com/55597077/67943779-b8953180-fbd2-11e9-86c1-761caef4f921.png">
