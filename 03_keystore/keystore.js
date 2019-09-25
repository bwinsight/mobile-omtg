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
