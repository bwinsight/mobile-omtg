# OMTG-Android - 04. Internal Storage - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys."<br />
> MSTG-STORAGE-2: "No sensitive data should be stored outside of the app container or system credential storage facilities."

**Summary of the challenge:** The challenge application stores sensitive data (credit card number) persistently in a file on the device's [internal storage](https://developer.android.com/guide/topics/data/data-storage.html#filesInternal). Files saved to internal storage are containerized by default and cannot be accessed by other apps until the device is not rooted. Sensitive data such as passwords, credit card information, PII are not properly protected when they are persistently stored on the device's internal storage in plain text format.

Using the following Frida script `04_internal_storage.js`, search for the classes `FileOutputStream` and `FileInputStream` to find out which files are written, opened and read within the app:
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
  var FileInputStream = {
    init: [
      Java.use("java.io.FileInputStream").$init.overload("java.io.File")
    ],
    read: [
      Java.use("java.io.FileInputStream").read.overload(),
      Java.use("java.io.FileInputStream").read.overload("[B", "int", "int")
    ],
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
    var TraceFD = {};
    var TraceFS = {};
    var TraceFile = {};

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
  FileInputStream.init[0].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null) {
      var p = file.getAbsolutePath();
      if (p !== null)
        fname = TraceFile["f" + file.hashCode()] = p;
    }
    if (fname == null)
      fname = "[unknow]"
    console.log("[*] New input stream from file (" + fname + "): ");
    var fis = FileInputStream.init[0].call(this, a0)
    var f = Java.cast(this, Java.use("java.io.FileInputStream"));
    TraceFS["fd" + this.hashCode()] = fname;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = fname;
    return fis;
  }
  FileInputStream.read[0].implementation = function() {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
      fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] Read from file, offset (" + fname + "):\n" +
    console.log(fname));
    return FileInputStream.read[0].call(this);
  }
  FileInputStream.read[1].implementation = function(a0, a1, a2) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
      fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    var b = Java.array('byte', a0);
    console.log("[*] Read from file, offset, length (" + fname + "," + a1 + "," + a2 + ")\n" +
    console.log(fname, b));
    return FileInputStream.read[1].call(this, a0, a1, a2);
  }
  FileOuputStream.init[0].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null)
      fname = "[unknow]<File:" + file.hashCode() + ">";
    console.log("[*] New output stream to file (" + fname + "): ");
    var fis = FileOuputStream.init[0].call(this, a0);
    TraceFS["fd" + this.hashCode()] = fname;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = fname;
    return fis;
  }
  FileOuputStream.init[1].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] New output stream to file (" + fname + "): \n");
    var fis = FileOuputStream.init[1].call(this, a0);
    TraceFS["fd" + this.hashCode()] = fname;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = fname;
    return fis;
  }
  FileOuputStream.init[2].implementation = function(a0) {
    var fd = Java.cast(a0, Java.use("java.io.FileDescriptor"));
    var fname = TraceFD["fd" + fd.hashCode()];
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] New output stream to FileDescriptor (" + fname + "): \n");
    var fis = FileOuputStream.init[2].call(this, a0)
    TraceFS["fd" + this.hashCode()] = fname;
    return fis;
  }
  FileOuputStream.init[3].implementation = function(a0) {
    console.log("[*] New output stream to file (str=" + a0 + "): \n");
    var fis = FileOuputStream.init[3].call(this, a0)
    TraceFS["fd" + this.hashCode()] = a0;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = a0;
    return fis;
  }
  FileOuputStream.init[4].implementation = function(a0) {
    console.log("[*] New output stream to file (str=" + a0 + ",bool): \n");
    var fis = FileOuputStream.init[4].call(this, a0)
    TraceFS["fd" + this.hashCode()] = a0;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = a0;
    return fis;
  }
  FileOuputStream.write[0].implementation = function(a0) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] Written into file (" + fname + "), output stream: " + a0);
    return FileOuputStream.write[0].call(this, a0);
  }
  FileOuputStream.write[1].implementation = function(a0, a1, a2) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    fname = TraceFD["fd" + fd.hashCode()]
    if (fname == null)
      fname = "[unknow], fd=" + this.hashCode();
    }
    console.log("[*] Written " + a2 + " bytes from " + a1 + " offset into file (" + fname + "), output stream: " + bytes2ascii(a0));
    return FileOuputStream.write[1].call(this, a0, a1, a2);
  }
});
```

Click on the InternalStorage button in the application and the sensitive file will be created:
<img src="https://user-images.githubusercontent.com/55597077/66270488-3a9c6f80-e84c-11e9-834e-59cff8b2cde3.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 04_internal_storage.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> [*] New file instance (/data/data/sg.vp.owasp_mobile.omtg_android/files)
[*] New file instance (/data/data/sg.vp.owasp_mobile.omtg_android/files/test_file)
[*] New output stream to file (/data/data/sg.vp.owasp_mobile.omtg_android/files/test_file):

[*] Written 41 bytes from 0 offset into file (/data/data/sg.vp.owasp_mobile.omtg_android/files/test_file), output stream: Credit Card Number is 1234 4321 5678 8765
```

The stored credit card number was `1234 4321 5678 8765` stored under the `/data/data/sg.vp.owasp_mobile.omtg_android/files/test_file` location.

Due to the fact the source code of the application wasn't obfuscated, it was possible to obtain the sensitive information by decompiling the apk file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_001_InternalStorage extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
    [...]
    try {
      writeFile();
    } catch (IOException e) {
      e.printStackTrace();
      }
  }
  private void writeFile() throws IOException {
    String string = "Credit Card Number is 1234 4321 5678 8765";
    FileOutputStream fos = null;
    try {
      fos = openFileOutput("test_file", 0);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
      }
    fos.write(string.getBytes());
    fos.close();
  }
}
```

Investigating the device's file system:
```bash
C:\>adb shell
shell@osprey_umts:/ $ su
shell@osprey_umts:/ # cd /data/data/sg.vp.owasp_mobile.omtg_android/files/
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/files # ls -la
-rw-rw---- u0_a120  u0_a120        41 2019-10-06 15:14 test_file
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/files # cat test_file
Credit Card Number is 1234 4321 5678 8765
```
