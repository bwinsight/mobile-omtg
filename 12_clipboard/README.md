# OMTG-Android - 12. Clipboard - Solution

> MSTG-STORAGE-6: "No sensitive data is exposed via IPC mechanisms."<br />

**Summary of the challenge:** The challenge is intended to prevent the use of copy/paste against text in the input field. 

Android has implemented clipboard framework to provide copy/paste function in applications. The clipboard is accessible system wide and can be used to copy user provided data between different applications. The fact is, this sharing mechanism can be misused by malicious applications to obtain sensitive information. Disabling paste function in password fields was a requirement in MASVS 1.0, but it was removed then due to: 
* it does not prevent users to copy sensitive information from other applications, so a malicious application can sniff the clipboard
* if users are not able to paste their passwords from password managers, they will choose weaker and memorable passwords

<img src="https://user-images.githubusercontent.com/55597077/67128071-91ae2700-f1f2-11e9-839f-08508b4e1e10.png" width="296">

However, there are mitigations to prevent pasting data from clipboard into an input field:
```java
sensitiveField.setCustomSelectionActionModeCallback(new ActionMode.Callback() {
  public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
    return false;
  }
  public void onDestroyActionMode(ActionMode mode) {
    return false; 
  }
  public boolean onCreateActionMode(ActionMode mode, Menu menu) {
    return false;
  }
  public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
    return false;
  }
});
```

Copy/pasting sensitive information is a known security risk, but may not be solved by this implementation due to the described reasons above.
