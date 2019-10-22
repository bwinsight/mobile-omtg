# OMTG-Android - 17. SQL Injection - Solution

> MSTG-ARCH-2: "Security controls are never enforced only on the client side, but on the respective remote endpoints."<br />
> MSTG-PLATFORM-2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

**Summary of the challenge:** SQL injection refers to an attack when the user input taints the backend database query with an SQL statement. Typical use case is adding characters with special meaning in a form field to execute malicious code on the database and provide access to the database or unauthorized logins on an Activity. The application is vulnerable against SQL injection, due to the lack of prepared statements in the database query:
```java
openOrCreateDatabase("authentication", 0, null).rawQuery("SELECT * FROM Accounts WHERE Username = '" + username + "' and Password = '" + password + "';", null);
```

The database query in the application can be terminated with the `' or 'a'='a` arbitrary SQL statement in the `password` field, in which case the application executes the `SELECT * FROM Accounts WHERE Username = 'admin' and Password = '' or 'a'='a';` query and returns with `true` boolean value bypassing the password validation of the login mechanism.

<img src="https://user-images.githubusercontent.com/55597077/67280759-c6a5cc80-f4c5-11e9-9aa1-a4e03d31511b.png" width="296">

Due to the source of the application is not obfuscated, it is possible to obtain the login credentials by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_CODING_003_SQL_Injection extends AppCompatActivity {
  Boolean login = Boolean.valueOf(false);
  EditText passwordText;
  EditText usernameText;
  [...]
    public void onClick(View v) {
      OMTG_CODING_003_SQL_Injection.this.login = Boolean.valueOf(OMTG_CODING_003_SQL_Injection.this.checkLogin(OMTG_CODING_003_SQL_Injection.this.usernameText.getText().toString(), OMTG_CODING_003_SQL_Injection.this.passwordText.getText().toString()));
      OMTG_CODING_003_SQL_Injection.this.toastOutput(OMTG_CODING_003_SQL_Injection.this.login);
    }
    
  public void toastOutput(Boolean login2) {
    if (login2.booleanValue()) {
      Toast.makeText(this, "User logged in", 1).show();
    } else {
      Toast.makeText(this, "Username and/or password wrong", 1).show();
    }
  }

  private void initializeDB(Context applicationContext) {
    if (!applicationContext.getDatabasePath("authentication").exists()) {
      SQLiteDatabase authentication = openOrCreateDatabase("authentication", 0, null);
      authentication.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
      authentication.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
      authentication.close();
    }
  }

  public boolean checkLogin(String username, String password) {
    Cursor cursor;
    Throwable th = null;
    boolean bool = false;
    try {
      cursor = openOrCreateDatabase("authentication", 0, null).rawQuery("SELECT * FROM Accounts WHERE Username = '" + username + "' and Password = '" + password + "';", null);
      Throwable th2 = null;
      [...]
    }
  }
}
```

Successful login with valid username and password combination:

<img src="https://user-images.githubusercontent.com/55597077/67286878-096da180-f4d2-11e9-9ff8-be9f7d874813.png" width="296">
