# OMTG-Android - 07. SQLite Not Encrypted - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys."<br />
> MSTG-STORAGE-2: "No sensitive data should be stored outside of the app container or system credential storage facilities."

**Summary of the challenge:** The challenge application stores sensitive data in unencrypted SQLite database file. Android provides support for SQLite databases by including and using the `android.database.sqlite` package. Due to sensitive information is stored in clear text, attackers could potentially read it.

The following Frida script `07_sqlite_not_encrypted.js` hooks the `java.io.File` class to identify the database location by monitoring the file system activities and hook the `android.database.sqlite.SQLiteDatabase` class to obtain the executed database queries:
```javascript
Java.perform(function() {
  //This class presents an abstract, system-independent view of hierarchical pathnames
  var File = Java.use("java.io.File");
  File.$init.overload('java.lang.String', 'java.lang.String').implementation = function(parent, child) {
  console.log("[*] File read : " + parent + "/" + child);
  var retval = this.$init(parent, child);
  return retval;
  }
  //This class has methods to create, delete, execute SQL commands and perform database management tasks
  var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
  sqliteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
    console.log("[*] SQLiteDatabase.exeqSQL method is called with query: " + sql);
    var retval = this.execSQL(sql);
    return retval;
  };
});
```

Click on the SQLite button in the application to create a new database:

<img src="https://user-images.githubusercontent.com/55597077/66956090-af955380-f05b-11e9-9608-e82b4b27b3d4.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 07_sqlite_not_encrypted.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> [*] File read : /data/data/sg.vp.owasp_mobile.omtg_android/databases
[*] File read : /data/data/sg.vp.owasp_mobile.omtg_android/databases/privateNotSoSecure
[*] SQLiteDatabase.exeqSQL method is called with query: CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);
[*] SQLiteDatabase.exeqSQL method is called with query: INSERT INTO Accounts VALUES('admin','AdminPass');
```

User credentials is stored in the `/data/data/sg.vp.owasp_mobile.omtg_android/databases/privateNotSoSecure` file.

Due to the fact the source code of the application is not obfuscated, it is possible to obtain the sensitive information by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_001_SQLite_Not_Encrypted extends AppCompatActivity {
  public void onCreate(Bundle savedInstanceState) {
  [...]
  SQLiteUnsafe();
  }

  private void SQLiteUnsafe() {
    SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure", 0, null);
    notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
    notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
    notSoSecure.close();
  }
}
```

Investigate the device file system in context of the application's sandbox:
```bash
C:\>adb shell
shell@osprey_umts:/ $ su
shell@osprey_umts:/ # id
uid=0(root) gid=0(root) context=u:r:magisk:s0
shell@osprey_umts:/ # cd /data/data/sg.vp.owasp_mobile.omtg_android/databases/
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/databases # ls -la
-rw-rw---- u0_a120  u0_a120     20480 2019-10-16 20:34 College
-rw------- u0_a120  u0_a120      8720 2019-10-16 20:34 College-journal
-rw-rw---- u0_a120  u0_a120     16384 2019-10-16 20:57 privateNotSoSecure
-rw------- u0_a120  u0_a120      8720 2019-10-16 20:57 privateNotSoSecure-journal
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/databases # cat privateNotSoSecure
Q�QT}tableAccountsAccountsCREATE TABLE Accounts(Username VARCHAR,Password VARCHAR)Wctableandroid_metadataandro
�adminAdminPassadminAdminPass
```
