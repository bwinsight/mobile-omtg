# OMTG-Android - 09. Logging - Solution

> MSTG-STORAGE-3: "No sensitive data is written to application logs."<br />

**Summary of the challenge:** The challenge application sends the provided user credentials to the `android.util.Log` class by invoking the `Log.e` method. Logging sensitive information may expose the data to malicious applications and violates user confidentiality.

To identify any potential logging activities, issue the `adb logcat` command in Terminal and click on the Logging button in the application then submit the form:

<img src="https://user-images.githubusercontent.com/55597077/67022045-7bbc3b80-f0f8-11e9-9cfc-e5a4fa98f829.png" width="377">

Observe the log output to identify the information leakage:
```bash
10-17 16:02:04.964  3040  3040 W IInputConnectionWrapper: getTextAfterCursor on inactive InputConnection
10-17 16:02:04.979  3040  3040 W IInputConnectionWrapper: getTextBeforeCursor on inactive InputConnection
10-17 16:02:04.981  3040  3040 W IInputConnectionWrapper: getTextAfterCursor on inactive InputConnection
10-17 16:02:05.025  1949  1949 I LatinIME: Starting input. Cursor position = 0,0
10-17 16:02:06.834   949  1597 I AccountManagerService: getTypesVisibleToCaller: isPermitted? true
10-17 16:02:16.028  3040  3040 E OMTG_DATAST_002_Logging: User successfully logged in. User: test_user Password: MyPW123
10-17 16:02:16.028  3040  3040 I System.out: WTF, Logging Class should be used instead.
```

Due to the fact the source code of the application is not obfuscated, it is possible to determine the security weakness by decompiling the APK file using [JADX-GUI](https://github.com/skylot/jadx):
```java
public class OMTG_DATAST_002_Logging extends AppCompatActivity {
  String TAG = "OMTG_DATAST_002_Logging";
  EditText passwordText;
  EditText usernameText;
  
  public void onCreate(Bundle savedInstanceState) {
  [...]
    this.usernameText = (EditText) findViewById(C0000R.id.loggingUsername);
    this.passwordText = (EditText) findViewById(C0000R.id.loggingPassword);
    ((Button) findViewById(C0000R.id.loginButton)).setOnClickListener(new OnClickListener() {
      public void onClick(View v) {
        OMTG_DATAST_002_Logging.this.CreateLogs(OMTG_DATAST_002_Logging.this.usernameText.getText().toString(), OMTG_DATAST_002_Logging.this.passwordText.getText().toString());
        }
      });
      [...]
    }

  public void CreateLogs(String username, String password) {
    Log.e(this.TAG, "User successfully logged in. User: " + username + " Password: " + password);
    System.out.println("WTF, Logging Class should be used instead.");
    Toast.makeText(this, "Log output has been created", 1).show();
  }
}
```
