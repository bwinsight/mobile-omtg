Java.perform(function() {
  
  //Java-AES-Crypto is a simple Android class for encrypting & decrypting strings
  var AesCbcWithIntegrity = Java.use("com.tozny.crypto.android.AesCbcWithIntegrity");
  
  //AES CBC decrypt
  //AesCbcWithIntegrity.decryptString(CipherTextIvMac civ, SecretKeys secretKeys)
  AesCbcWithIntegrity.decryptString.overload('com.tozny.crypto.android.AesCbcWithIntegrity$CipherTextIvMac', 'com.tozny.crypto.android.AesCbcWithIntegrity$SecretKeys').implementation = function(civ, secretKeys) {
    console.log("[*] decryptString method is called, with civ: " + civ); //civ: the cipher text, IV, and mac
    console.log("[*] decryptString method is called, with secretKeys: " + secretKeys); //secretKeys: the AES and HMAC keys
    var retval = this.decryptString(civ,secretKeys); //a string derived from the decrypted bytes
    console.log("[*] Decypted string: " + retval);
    return retval;
  };
});
