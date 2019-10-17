# OMTG-Android - 10. 3rd Party - Solution

> MSTG-STORAGE-4: "No sensitive data is shared with third parties unless it is a necessary part of the architecture."<br />

**Summary of the challenge:** The challenge application is embedded a 3rd-party service to send a detailed report about the device upon application crash in order to improve the user experience. That behaviour violates user confidentiality. The downside of this implementation is that the application developer is not aware of what code is executed via 3rd-party libraries. Important to ensure that no sensitive information is disclosed to unknown services.

To identify the information leakage, the HTTP traffic needs to be captured by a web interception proxy, such as Burp Suite. Click on the 3rd Party then the Crash The App buttons and observe the traffic:

<img src="https://user-images.githubusercontent.com/55597077/67048431-184c0100-f12c-11e9-8e85-2a466736a842.png" width="377">

The following request is sent from the application containing sensitive information e.g. device model or serial among others:
```http
POST /acra/_design/acra-storage/_update/report HTTP/1.1
Authorization: Basic TW1IWk9xeEFkVDBtV1NtWGRkWUJkTFBEbzpNbUhaT3F4QWRUMG1XU21YZGRZQmRMUERv
User-Agent: Android ACRA 4.9.0
Accept: text/html,application/xml,application/json,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Content-Type: application/json
Content-Length: 2743
Host: sushi2k.cloudant.com
Connection: close
Accept-Encoding: gzip, deflate

{
   "REPORT_ID":"36fddc0e-0b15-4e6f-8ad4-5be1de8156e3",
   "APP_VERSION_CODE":1,
   "APP_VERSION_NAME":"1.0",
   "PACKAGE_NAME":"sg.vp.owasp_mobile.omtg_android",
   "ANDROID_VERSION":"5.1.1",
   "BUILD":{
      "BOARD":"msm8916",
      "BOOTLOADER":"0x8090",
      "BRAND":"motorola",
      "CPU_ABI":"armeabi-v7a",
      "CPU_ABI2":"armeabi",
      "DEVICE":"osprey_umts",
      "DISPLAY":"LPI23.72-47",
      "FINGERPRINT":"motorola\/osprey_retgb\/osprey_umts:5.1.1\/LPI23.72-47\/50:user\/release-keys",
      "HARDWARE":"qcom",
      "HOST":"ilclbld52",
      "ID":"LPI23.72-47",
      "IS_DEBUGGABLE":false,
      "MANUFACTURER":"motorola",
      "MODEL":"<<REMOVED>>",
      "PRODUCT":"osprey_retgb",
      "RADIO":"unknown",
      "SERIAL":"<<REMOVED>>",
      "SUPPORTED_32_BIT_ABIS":"[armeabi-v7a, armeabi]",
      "SUPPORTED_64_BIT_ABIS":"[]",
      "SUPPORTED_ABIS":"[armeabi-v7a, armeabi]",
      "TAGS":"release-keys",
      "TIME":1437631737000,
      "TYPE":"user",
      "UNKNOWN":"unknown",
      "USER":"hudsoncm",
      "VERSION":{
         "ACTIVE_CODENAMES":"[]",
         "CODENAME":"REL",
         "INCREMENTAL":50,
         "RELEASE":"5.1.1",
         "RESOURCES_SDK_INT":22,
         "SDK":22,
         "SDK_INT":22
      }
   },
   "TOTAL_MEM_SIZE":4863164416,
   "AVAILABLE_MEM_SIZE":1150984192,
   "STACK_TRACE":"java.lang.RuntimeException: This is a crash\n\tat sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_004_3rd_Party.CrashApp(OMTG_DATAST_004_3rd_Party.java:36)\n\tat sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_004_3rd_Party.access$000(OMTG_DATAST_004_3rd_Party.java:9)\n\tat sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_004_3rd_Party$1.onClick(OMTG_DATAST_004_3rd_Party.java:27)\n\tat android.view.View.performClick(View.java:4785)\n\tat android.view.View$PerformClick.run(View.java:19884)\n\tat android.os.Handler.handleCallback(Handler.java:746)\n\tat android.os.Handler.dispatchMessage(Handler.java:95)\n\tat android.os.Looper.loop(Looper.java:135)\n\tat android.app.ActivityThread.main(ActivityThread.java:5343)\n\tat java.lang.reflect.Method.invoke(Native Method)\n\tat java.lang.reflect.Method.invoke(Method.java:372)\n\tat com.android.internal.os.ZygoteInit$MethodAndArgsCaller.run(ZygoteInit.java:905)\n\tat com.android.internal.os.ZygoteInit.main(ZygoteInit.java:700)\n",
   "DISPLAY":{
      "0":{
         "currentSizeRange":{
            "smallest":"[720,670]",
            "largest":"[1196,1134]"
         },
         "flags":"FLAG_SUPPORTS_PROTECTED_BUFFERS+FLAG_SECURE",
         "height":1184,
         "metrics":{
            "density":"2.0",
            "densityDpi":320,
            "scaledDensity":"x2.0",
            "widthPixels":720,
            "heightPixels":1184,
            "xdpi":294.967,
            "ydpi":295.563
         },
         "name":"Built-in Screen",
         "orientation":0,
         "pixelFormat":1,
         "realMetrics":{
            "density":"2.0",
            "densityDpi":320,
            "scaledDensity":"x2.0",
            "widthPixels":720,
            "heightPixels":1280,
            "xdpi":294.967,
            "ydpi":295.563
         },
         "realSize":"[720,1280]",
         "rectSize":"[0,0,720,1184]",
         "refreshRate":"60.0",
         "rotation":"ROTATION_0",
         "size":"[720,1184]",
         "width":720,
         "isValid":true
      }
   },
   "USER_APP_START_DATE":"2019-10-17T22:09:53.536+01:00",
   "USER_CRASH_DATE":"2019-10-17T22:10:07.684+01:00"
}
```

Due to the fact the source code of the application is not obfuscated, it is possible to decompile the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_004_3rd_Party extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
    [...]
    ((Button) findViewById(C0000R.id.crashButton)).setOnClickListener(new OnClickListener() {
      public void onClick(View v) {
        OMTG_DATAST_004_3rd_Party.this.CrashApp();
      }
    });
  }
  public void CrashApp() {
    throw new RuntimeException("This is a crash");
  }
}
```
