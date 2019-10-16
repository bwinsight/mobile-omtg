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
