Java.perform(function() {
  //This class presents an abstract, system-independent view of hierarchical pathnames
  //var File = Java.use("java.io.File");
  //File.$init.overload('java.lang.String', 'java.lang.String').implementation = function(parent, child) {
  //  console.log("[*] File read: " + parent + "/" + child);
  //  var retval = this.$init(parent, child);
  //  return retval;
  //}
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
