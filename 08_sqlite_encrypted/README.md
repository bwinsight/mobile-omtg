# OMTG-Android - 08. SQLite Encrypted - Solution

> MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys."<br />
> MSTG-STORAGE-2: "No sensitive data should be stored outside of the app container or system credential storage facilities."

**Summary of the challenge:** The challenge application stores sensitive data in encrypted SQLite database file by including and using the `net.sqlcipher.database.SQLiteDatabase` package. Due to sensitive information is stored in encrypted format, the encryption key should never reside on the same location where the encrypted data is stored.

The following Frida script `08_sqlite_encrypted.js` hooks the `android.content.ContextWrapper` class to print the database location which is the input parameter of the `getDatabasePath` method. The `net.sqlcipher.database.SQLiteDatabase` class is used to open or create the encrypted database file and execute queries. Since the database password is hardcoded in the external source it can be retrieved by hooking the `openOrCreateDatabase` method:
```javascript
Java.perform(function() {
  //Returns the absolute path on the filesystem where a database is stored
  var ContextWrapper = Java.use("android.content.ContextWrapper");
  ContextWrapper.getDatabasePath.overload('java.lang.String').implementation = function(name) {
    console.log("[*] Database name: " + name);
    var retval = this.getDatabasePath(name);
    console.log("[*] Database path: " + retval);
    return retval;
  }
  //Open an SQLiteDatabase or create the database file if it doesn't exist
  var netSQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
  netSQLiteDatabase.openOrCreateDatabase.overload('java.io.File', 'java.lang.String', 'net.sqlcipher.database.SQLiteDatabase$CursorFactory').implementation = function(file, password, factory) { 
    console.log("[*] Database is opened or created with password: " + password);
    var retval = this.openOrCreateDatabase(file, password, factory);
    return retval;
  };
  //Execute SQL commands against the database
  netSQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
    console.log("[*] SQLiteDatabase.exeqSQL method is called with query: " + sql);
    var retval = this.execSQL(sql);
    return retval;
  };
});
```

Click on the SQLite Encrypted button in the application to create a new database:

<img src="https://user-images.githubusercontent.com/55597077/66962657-7663e000-f069-11e9-95e7-2b8cb6d071f6.png" width="377">

Frida console output:
```bash
C:\>frida -U sg.vp.owasp_mobile.omtg_android -l 08_sqlite_encrypted.js --no-pause
     ____
    / _  |   Frida 12.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Motorola::sg.vp.owasp_mobile.omtg_android]-> [*] Database name: encrypted
[*] Database path: /data/data/sg.vp.owasp_mobile.omtg_android/databases/encrypted
[*] Database is opened or created with password: S3cr3tString!!!
[*] SQLiteDatabase.exeqSQL method is called with query: CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);
[*] SQLiteDatabase.exeqSQL method is called with query: INSERT INTO Accounts VALUES('admin','AdminPassEnc');
```

User credentials is stored in the `/data/data/sg.vp.owasp_mobile.omtg_android/databases/encrypted` file.

Due to the fact the source code of the application is not obfuscated, it is possible to obtain the sensitive information by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_001_SQLite_Encrypted extends AppCompatActivity {
  public native String stringFromJNI();
  @TargetApi(23)
  public void onCreate(Bundle savedInstanceState) {
  [...]
  SQLiteEnc();
  }
  static {
    System.loadLibrary("native");
  }
  private void SQLiteEnc() {
    SQLiteDatabase.loadLibs(this);
    File database = getDatabasePath("encrypted");
    database.mkdirs();
    database.delete();
    SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, stringFromJNI(), (CursorFactory) null);
    secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
    secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
    secureDB.close();
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
-rw------- u0_a120  u0_a120      3072 2019-10-16 22:59 encrypted
-rw-rw---- u0_a120  u0_a120     16384 2019-10-16 20:57 privateNotSoSecure
-rw------- u0_a120  u0_a120      8720 2019-10-16 20:57 privateNotSoSecure-journal
shell@osprey_umts:/data/data/sg.vp.owasp_mobile.omtg_android/databases # cat encrypted
L�~ߊ�e�3�H��w�O�!�����ȵƠ�ץ����)P<F���NT������TA��И]<�~@BҍO���C��
ȱ[�AV��c�p'_�cz\��%�SI;�dF/B^��w�|(�a�S�i���p�z��O*e� SR-&6�0��P0sK4E�۫*J^a�}G�b�*�K��a��� la��/ڍH����>�WE�H��~e�����a��*Sik|���s� ������X!D<���j��Ayl�Zw,{��ū
[...]
```
