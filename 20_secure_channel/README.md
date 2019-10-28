# OMTG-Android - 20. Secure Channel - Solution

> MSTG-NETWORK-1: "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."

**Summary of the challenge:** The application is trying to access and load the `example.com` URL using WebView once with `http` and once with `https` protocols. This challenge demonstrates that communication channel over HTTP is insecure, as all the traffic can be intercepted, monitored and modified by establishing Man-in-the-Middle attack if an attacker has access to the same network (e.g. through Wi-Fi access point). Connection over HTTPS allows authentication of the backend service and ensures confidentiality and integrity of the network data.

Due to the source of the application is not obfuscated, the APK file can be decompiled by the use of [JADX-GUI](https://github.com/skylot/jadx) tool to allow analysis of the implemented methods:
```java
public class OMTG_NETW_001_Secure_Channel extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
    [...]
    WebView secure = (WebView) findViewById(C0000R.id.webView2);
    ((WebView) findViewById(C0000R.id.webView1)).loadUrl(getResources().getString(C0000R.string.url_example));
    secure.loadUrl(getResources().getString(C0000R.string.url_example_ssl));
  }
}
```

Strings.xml:
```xml
<string name="url_example">http://example.com</string>
<string name="url_example_ssl">https://example.com</string>

```

To capture the HTTP traffic with an interception proxy like Burp Suite, configure the proxy settings for each Wi-Fi network. Open Android's Settings application => Wi-Fi, to view a list of available networks => long press the name of the connected Wi-Fi network => Modify network => Advanced options => set Proxy option to Manual and provide the proxy server's IP address and port number.

<img src="https://user-images.githubusercontent.com/55597077/67711090-25cd7a80-f9b9-11e9-9227-7e67ad78aa11.png" width="296">

The following Frida script `20_secure_channel.js` hooks the `android.webkit.WebView` class to print all the URLs are loaded into WebView objects in runtime:
```javascript
Java.perform(function() {
  
  var WebView = Java.use("android.webkit.WebView");
  
  //Loads the given URL
  //WebView.loadUrl (String url)
  WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
    console.log("[*] Loaded URL into WebView: " + url);
    this.loadUrl.overload('java.lang.String').call(this, url);
   };
  //WebView.loadUrl (String url, Map<String, String> additionalHttpHeaders)
  WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, additionalHttpHeaders) {
    console.log("[*] Loaded URL into WebView: " + url);
    this.loadUrl.overload('java.lang.String', 'java.util.Map').call(this, url, additionalHttpHeaders);
   };
});
```

Tap on the Secure Channel button to initiate the remote connections over HTTP and HTTPS protocols.

<img src="https://user-images.githubusercontent.com/55597077/67711088-2534e400-f9b9-11e9-8831-4f9b07a48e0a.png" width="296">

Only the HTTP connection has been loaded through and monitored by the Burp Suite proxy:

<img src="https://user-images.githubusercontent.com/55597077/67713379-a2faee80-f9bd-11e9-8bcd-db508b782dcc.png">

Frida console output about the invoked URLs:
```cmd
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 20_secure_channel.js --no-pause
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
[*] Loaded URL into WebView: http://example.com
[*] Loaded URL into WebView: https://example.com
```
