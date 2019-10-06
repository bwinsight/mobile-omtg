# OMTG-Android - 05. External Storage - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys."<br />
> MSTG-STORAGE-2: "No sensitive data should be stored outside of the app container or system credential storage facilities."

**Summary of the challenge:** The challenge application stores sensitive data (password) persistently in a text file on the device's [external storage](https://developer.android.com/guide/topics/data/data-storage.html#filesExternal). That storage can be removable (SD card) or internal (non-removable). Files saved to external storage are world read/writeable since the read/write external storage permissions have to be granted `android.permission.READ_EXTERNAL_STORAGE`, `android.permission.WRITE_EXTERNAL_STORAGE`. Files stored outside the application folder (data/data/application.package.name/) will not be deleted upon the application uninstall. Sensitive data such as passwords, credit card information, PII are not properly protected when they are stored on the device's external storage in plain text format.

Using the following Frida script `05_external_storage.js`, search for the class `FileOutputStream` to find out which files are written within the app:
```javascript
function bytes2ascii(array) {
  var result = "";
  for(var i = 0; i < array.length; ++i) {
    result+= (String.fromCharCode(array[i]));
  }
  return result;
}

Java.perform(function() {
  //Load classes that operate on files into variables
  var File = {
    init: [
      Java.use("java.io.File").$init.overload("java.lang.String"),
      Java.use("java.io.File").$init.overload("java.lang.String", "java.lang.String")
    ]
  };
  var FileOuputStream = {
    init: [
      Java.use("java.io.FileOutputStream").$init.overload("java.io.File"),
      Java.use("java.io.FileOutputStream").$init.overload("java.io.File", "boolean"),
      Java.use("java.io.FileOutputStream").$init.overload("java.io.FileDescriptor"),
      Java.use("java.io.FileOutputStream").$init.overload("java.lang.String"),
      Java.use("java.io.FileOutputStream").$init.overload("java.lang.String", "boolean")
    ],
    write: [
      Java.use("java.io.FileOutputStream").write.overload("int"),
      Java.use("java.io.FileOutputStream").write.overload("[B", "int", "int")
    ],
  };
  
  //Arrays for file descriptor, path, file
  var TraceFile = {};
  var TraceFS = {};

  //Hook the relevant file activity methods
  File.init[0].implementation = function(a0) {
    console.log("[*] New file instance (" + a0 + ")");
    var ret = File.init[0].call(this, a0);
    var f = Java.cast(this, Java.use("java.io.File"));
    TraceFile["f" + this.hashCode()] = a0;
    return ret;
  }
  File.init[1].implementation = function(a0, a1) {
    console.log("[*] New file instance (" + a0 + "/" + a1 + ")");
    var ret = File.init[1].call(this, a0, a1);
    var f = Java.cast(this, Java.use("java.io.File"));
    TraceFile["f" + this.hashCode()] = a0 + "/" + a1;
    return ret;
  }
  FileOuputStream.init[1].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] New output stream to file (" + fname + "): \n");
    var fis = FileOuputStream.init[1].call(this, a0);
    return fis;
  }
  FileOuputStream.write[1].implementation = function(a0, a1, a2) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    if (fname == null)
      fname = "[unknow], fd=" + this.hashCode();
    }
    console.log("[*] Written " + a2 + " bytes from " + a1 + " offset into file (" + fname + "), output stream: " + bytes2ascii(a0));
    return FileOuputStream.write[1].call(this, a0, a1, a2);
  }
});
```

Click on the ExternalStorage button in the application and the sensitive file will be created:
<img src="https://user-images.githubusercontent.com/55597077/66275000-56b80500-e87c-11e9-98f9-56e58d2ad9be.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 05_external_storage.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> [*] New file instance (/storage/emulated/0)
[*] New file instance (/storage/emulated/0)
[*] New file instance (/storage/sdcard1)
[*] New file instance (/storage/usbdisk)
[*] New file instance (/storage/emulated/0/password.txt)
[*] New output stream to file (/storage/emulated/0/password.txt):

[*] Written 10 bytes from 0 offset into file ([unknow], fd=191180130), output stream: L33tS3cr3t
```

The password `L33tS3cr3t` was stored under the `/storage/emulated/0/password.txt` location.

Due to the fact the source code of the application wasn't obfuscated, it was possible to obtain the sensitive information by decompiling the apk file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_001_ExternalStorage extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
  [...]
  if (isExternalStorageWritable()) {
    String password = "L33tS3cr3t";
    try {
      FileOutputStream fos = new FileOutputStream(new File(Environment.getExternalStorageDirectory(), "password.txt"));
      fos.write(password.getBytes());
      fos.close();
    }
  [...]
}
```

Investigating the device's file system:
```bash
C:\>adb shell
shell@osprey_umts:/ $ cd /sdcard
shell@osprey_umts:/sdcard $ ls -la password.txt
-rw-rw---- root     sdcard_r       10 2019-10-06 20:58 password.txt
shell@osprey_umts:/sdcard $ cat password.txt
L33tS3cr3t
```
