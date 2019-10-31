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