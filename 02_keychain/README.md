# OMTG-Android - 02. KeyChain - Solution

> MSTG-NETWORK-3:	"The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."


**Summary of the challenge:** The mobile user is manipulated to install a root certificate on his device, the result of this may allow the owner of the root certificate (attacker) to inspect all traffic to and from the device.

The following code snippet allows the user to install the malicious root certificate into the Android KeyChain. The method can be found under the `sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyChain` class:
```java
private void installPkcs12() {
        try {
            for (String f1 : getAssets().list("")) {
                Log.v("names", f1);
            }
            BufferedInputStream bis = new BufferedInputStream(getAssets().open(PKCS12_FILENAME));
            byte[] keychain = new byte[bis.available()];
            bis.read(keychain);
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra("PKCS12", keychain);
            startActivity(installIntent);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e2) {
            e2.printStackTrace();
        }
    }

```

Once the app is loaded, the `installPkcs12()` method will be called to install the embedded `server.p12` certificate file:

<img src="https://user-images.githubusercontent.com/55597077/65363791-aef8d100-dc05-11e9-80e2-23b789ce6702.png" width="377">

After the user provides the password, the root certificate will be installed:

<img src="https://user-images.githubusercontent.com/55597077/65363792-aef8d100-dc05-11e9-8f7d-ea96319933f9.png" width="377">

The malicious certificate has been added to the KeyChain and now trusted. Note that if the device owner use neither a PIN, nor a password to unlock the screen, importing a CA certificate might require him to improve his device security first.

<img src="https://user-images.githubusercontent.com/55597077/65363805-b8823900-dc05-11e9-8e4d-f273f82e8e31.png" width="377">
