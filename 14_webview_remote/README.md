# OMTG-Android - 14. WebView Remote - Solution

> MSTG-PLATFORM-5: "JavaScript is disabled in WebViews unless explicitly required."

**Summary of the challenge:** The application is loading a remote URL to display a HTML page using WebView component. Due to the support of JavaScript execution is explicitly enabled, the application is vulnerable against Cross-Site Scripting (XSS) attack by injecting malicious JavaScript content into the loaded web page. JavaScript can be used to access local resources, although some restrictions may be enforced. Moreover, WebView is exposing a Java object's method to be accessed from JavaScript by using reflection.

In order to determine the use of the WebView class and the enabled interfaces, decompile the APK file using [JADX-GUI](https://github.com/skylot/jadx) and search for `WebView` object in the source:
```java
public class OMTG_ENV_005_WebView_Remote extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
  [...]
    public void onClick(View v) {
      ((WebView) OMTG_ENV_005_WebView_Remote.this.findViewById(C0000R.id.webView1)).reload();
    }
    WebView myWebView = (WebView) findViewById(C0000R.id.webView1);
    myWebView.setWebChromeClient(new WebChromeClient());
    myWebView.getSettings().setJavaScriptEnabled(true);
    myWebView.addJavascriptInterface(new OMTG_ENV_005_JS_Interface(this), "Android");
    myWebView.loadUrl("https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm");
  }
}

public class OMTG_ENV_005_JS_Interface {
  Context mContext;
  OMTG_ENV_005_JS_Interface(Context c) {
    this.mContext = c;
  }
  public OMTG_ENV_005_JS_Interface() {
  }
  public String returnString() {
    return "Secret String";
  }
  public void showToast(String toast) {
    Toast.makeText(this.mContext, toast, 0).show();
  }
}
```

The WebView rendering engine loads the `https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm` URL and the embedded JavaScript code is executed.

<img src="https://user-images.githubusercontent.com/55597077/67165797-2a72ad00-f381-11e9-907f-c12160787be9.png" width="296">

Content of the remotely accessed `webview.htm` HTML file:
```html
<HTML>
<body>
<h1 style="color: #5e9ca0;">This is a remote test page!</h1>
<p id="p1">2</p>
<input type="button" value="Press here to trigger Toast Message" onclick="fireToastMessage()" />
  <script>
	//check if JavaScript is activated
  alert(43);	
  
  var file = "file://storage/emulated/0/password.txt";
  var xhr = new XMLHttpRequest();
  xhr.overrideMimeType("text/plain; charset=iso-8859-1");
  xhr.open("GET", file, true);
  xhr.onreadystatechange = function() {
    var data = xhr.responseText;
    // alert(data);
  }
  xhr.send();
	
  var result = window.Android.returnString();
  document.getElementById("p1").innerHTML = result;
	
  function fireToastMessage() {
    window.Android.showToast("this is executed by JavaScript"); 
  }
  </script>
  </body>
  </HTML>
```

Java methods `returnString()` and `showToast(String toast)` are called using the WebView JavaScript bridge, named `Android` to reveal a hidden text and in order to show a toast message in the application.

<img src="https://user-images.githubusercontent.com/55597077/67165799-2a72ad00-f381-11e9-90ab-7c93160f7188.png" width="296">

The following Frida script `14_webview_remote.js` hooks the `android.webkit.WebView` class to print all the URLs are loaded into WebView objects and identify the Java object's methods are accessible from JavaScript to execute arbitrary codes on Java level:
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
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 14_webview_remote.js --no-pause
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
[*] Java object's methods is accessed from JavaScript: Android
[*] Loaded URL into WebView: https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm
```
