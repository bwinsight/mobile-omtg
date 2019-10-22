# OMTG-Android - 16. Best Practice - Solution

> MSTG-ARCH-2: "Security controls are never enforced only on the client side, but on the respective remote endpoints."<br />
> MSTG-PLATFORM-2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

**Summary of the challenge:** SQL injection refers to an attack when the user input taints the backend database query with an SQL statement. Typical use case is adding characters with special meaning in a form field to execute malicious code on the database and provide access to the database or unauthorized logins on an Activity. The security best practice is followed in this challenge level. The application is not vulnerable against SQL injection, due to the use of prepared statements in the database query:
```java
openOrCreateDatabase("authentication-best-practice", 0, null).rawQuery("SELECT * FROM Accounts WHERE Username=? and Password=?", new String[]{username, password});
```

The database query can not be terminated with arbitrary commands:

<img src="https://user-images.githubusercontent.com/55597077/67276643-0a480880-f4bd-11e9-9c74-bf329ce56734.png" width="296">

Due to the source of the application is not obfuscated, it is possible to obtain the login credentials by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_CODING_003_Best_Practice extends AppCompatActivity {
  Boolean login = Boolean.valueOf(false);
  EditText passwordText;
  EditText usernameText;
  [...]
  public void onClick(View v) {
    OMTG_CODING_003_Best_Practice.this.login = Boolean.valueOf(OMTG_CODING_003_Best_Practice.this.checkLogin(OMTG_CODING_003_Best_Practice.this.usernameText.getText().toString(), OMTG_CODING_003_Best_Practice.this.passwordText.getText().toString()));
    OMTG_CODING_003_Best_Practice.this.toastOutput(OMTG_CODING_003_Best_Practice.this.login);
  }
   
  public void toastOutput(Boolean login2) {
    if (login2.booleanValue()) {
      Toast.makeText(this, "User logged in", 1).show();
    } else {
      Toast.makeText(this, "Username and/or password wrong", 1).show();
    }
  }

  private void initializeDB(Context applicationContext) {
    if (!applicationContext.getDatabasePath("authentication-best-practice").exists()) {
      SQLiteDatabase authentication = openOrCreateDatabase("authentication-best-practice", 0, null);
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
     cursor = openOrCreateDatabase("authentication-best-practice", 0, null).rawQuery("SELECT * FROM Accounts WHERE Username=? and Password=?", new String[]{username, password});
     [...]
   }
 }
}
```

Successful login with valid username and password combination:

<img src="https://user-images.githubusercontent.com/55597077/67276642-0a480880-f4bd-11e9-8f19-6778f2d05b73.png" width="296">
