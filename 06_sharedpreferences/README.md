# OMTG-Android - 06. SharedPreferences - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys."<br />
> MSTG-STORAGE-2: "No sensitive data should be stored outside of the app container or system credential storage facilities."

**Summary of the challenge:** The challenge application stores sensitive data (user credentials) persistently in the [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences) using clear text XML file on the device's [internal storage](https://developer.android.com/guide/topics/data/data-storage.html#filesInternal). SharedPreferences object can be declared as world readable due to it can be accessible to every application on the user's device. Sensitive data are not properly protected in clear text format.

Using the following Frida script `06_sharedpreferences.js` it is possible to observe the update activities of the SharedPreferences objects:
```javascript
Java.perform(function() {

  var spFile = "";

  var ContextWrapper = Java.use("android.content.ContextWrapper");
  ContextWrapper.getSharedPreferences.overload("java.lang.String", "int").implementation = function (spName, spMode) {
    console.log("SharedPreferences putString activity monitor script");
    spFile = spName;
    return this.getSharedPreferences(spName, spMode);
  };

  var sharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
  sharedPreferencesEditor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(spKey, spValue) { 
    console.log("[+] SharedPreferences file \"" + spFile + "\" is written with key: \"" + spKey + "\" and value \"" + spValue + "\"");
    var editor = this.putString(spKey, spValue); 
    return editor;
  };
});
```

Click on the Shared Preferences button in the application to initiate update on SharedPreferences:
<img src="https://user-images.githubusercontent.com/55597077/66688850-59ea3100-ec80-11e9-9943-b82fcff59c84.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 06_sharedpreferences.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> SharedPreferences putString activity monitor script
[+] SharedPreferences file "key" is written with key: "username" and value "administrator"
[+] SharedPreferences file "key" is written with key: "password" and value "supersecret"
```

User credentials were stored in the `/data/data/sg.vp.owasp_mobile.omtg_android/shared_prefs/key.xml` file.

Due to the fact the source code of the application wasn't obfuscated, it was possible to obtain the sensitive information by decompiling the apk file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_001_SharedPreferences extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
  [...]
  Editor editor = getSharedPreferences("key", 1).edit();
  editor.putString("username", "administrator");
  editor.putString("password", "supersecret");
  editor.commit();
  }
}
```

Investigate the device file system, SharedPreferences (key.xml) is readable by any applications:
```bash
C:\>adb shell
shell@osprey_umts:/ $ su
shell@osprey_umts:/ # cd data/data/sg.vp.owasp_mobile.omtg_android/shared_pref
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/shared_prefs # ls -la
-rw-rw-r-- u0_a120  u0_a120       170 2019-10-11 22:15 key.xml
-rw-rw---- u0_a120  u0_a120       189 2019-10-06 20:37 sg.vp.owasp_mobile.omtg_android_preferences.xml
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/shared_prefs # cat key.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">administrator</string>
    <string name="password">supersecret</string>
</map>
shell@osprey_umts:/ # exit
shell@osprey_umts:/ $ id
uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:shell:s0
shell@osprey_umts:/ $ cat /data/data/sg.vp.owasp_mobile.omtg_android/shared_prefs/key.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">administrator</string>
    <string name="password">supersecret</string>
</map>
```
