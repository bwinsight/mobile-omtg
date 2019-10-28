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
