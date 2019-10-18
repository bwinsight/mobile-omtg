# OMTG-Android - 11. Keyboard Cache - Solution

> MSTG-STORAGE-5: "The keyboard cache is disabled on text inputs that process sensitive data."<br />

**Summary of the challenge:** The challenge asks the user to type some sensitive data into an input field. The provided text won't be added to the keyboard application's cache due to the `android:inputType` attribute has the `textNoSuggestions` setting in the layout definition XML file. In this case keyboard applications cannot leak sensitive information to any 3rd party service. 

The keyboard application is not listing the previously typed words:

<img src="https://user-images.githubusercontent.com/55597077/67122485-d1224680-f1e5-11e9-9350-af624b4eed6a.png" width="377">

The `textNoSuggestions` setting disables the keyboard suggestions. It is possible to decompile the APK file using [JADX-GUI](https://github.com/skylot/jadx) to obtain the `/res/layout/activity_omtg__datast_005__keyboard__cache.xml` layout file:
```xml
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto" android:paddingLeft="@dimen/activity_horizontal_margin" android:paddingTop="@dimen/activity_vertical_margin" android:paddingRight="@dimen/activity_horizontal_margin" android:paddingBottom="@dimen/activity_vertical_margin" android:layout_width="match_parent" android:layout_height="match_parent" app:layout_behavior="@string/appbar_scrolling_view_behavior">
    <TextView android:id="@+id/KeyBoardCacheTextView" android:paddingTop="10px" android:layout_width="wrap_content" android:layout_height="wrap_content" android:text="@string/textview_OMTG_DATAST_005_Keyboard_Cache"/>
    <EditText android:id="@+id/KeyBoardCache" android:layout_width="match_parent" android:layout_height="wrap_content" android:hint="@string/title_activity_omtg__datast_052__keyboard_cache" android:layout_below="@+id/KeyBoardCacheTextView" android:layout_centerHorizontal="true" android:inputType="textNoSuggestions"/>
</RelativeLayout>
```
