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
