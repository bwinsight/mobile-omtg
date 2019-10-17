Java.perform(function() {
  
  //////////////////////////
  //File system activities//
  //////////////////////////
  
  //This class presents an abstract, system-independent view of hierarchical pathnames
  var File = Java.use("java.io.File");
  
  //File (String parent, String child)
  File.$init.overload('java.lang.String', 'java.lang.String').implementation = function(parent, child) {
    console.log("[*] [File] New file instance: " + parent + "/" + child);
    var retval = this.$init(parent, child);
    return retval;
  }
  
  //File (String pathname)
  File.$init.overload('java.lang.String').implementation = function(pathname) {
    console.log("[*] [File] New file instance: " + pathname);
    var retval = this.$init(pathname);
    return retval;
  }
  
  //File (File parent, String child)
  File.$init.overload('java.io.File', 'java.lang.String').implementation = function(parent, child) {
    console.log("[*] [File] New file instance: " + parent + "/" + child);
    var retval = this.$init(parent, child);
    return retval;
  }
  
  //File (URI uri)
  File.$init.overload('java.net.URI').implementation = function(uri) {
    console.log("[*] [File] New file URI instance: " + uri);
    var retval = this.$init(uri);
    return retval;
  }
  
  //////////////////////////////////////////////////
  //Application ContextWrapper - Database location//
  //////////////////////////////////////////////////
  
  //Returns the absolute path on the filesystem where a database is stored
  var ContextWrapper = Java.use("android.content.ContextWrapper");
  ContextWrapper.getDatabasePath.overload('java.lang.String').implementation = function(name) {
    console.log("[*] [ContextWrapper] Database name: " + name);
    var retval = this.getDatabasePath(name);
    console.log("[*] [ContextWrapper] Database path: " + retval);
    return retval;
  }
  
  //////////////////////////////////////////////
  //Application Context - openOrCreateDatabase//
  //////////////////////////////////////////////
  
  var context = Java.use("android.content.Context");
  //SQLiteDatabase.openOrCreateDatabase(String name, int mode, SQLiteDatabase.CursorFactory factory)
  context.openOrCreateDatabase.overload('java.lang.String', 'int', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function(name, mode, factory) {
    var mode_name = "";
    switch(mode) {
      case 0:
        mode_name = "MODE_PRIVATE";
        break;
      case 1:
        mode_name = "MODE_WORLD_READABLE";
        break;
      case 2:
        mode_name = "MODE_WORLD_WRITEABLE";
        break;
      case 8:
        mode_name = "MODE_ENABLE_WRITE_AHEAD_LOGGING";
        break;
      case 16:
        mode_name = "MODE_NO_LOCALIZED_COLLATORS";
        break;
      default:
	    mode_name = "";
    }
	console.log("[*] [Context] openOrCreateDatabase method is called with mode: " + mode_name);
    var retval = this.openOrCreateDatabase(name, mode, factory);
    return retval;
  };

  //SQLiteDatabase.openOrCreateDatabase(String name, int mode, SQLiteDatabase.CursorFactory factory, DatabaseErrorHandler errorHandler) 
    context.openOrCreateDatabase.overload('java.lang.String', 'int', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'android.database.DatabaseErrorHandler').implementation = function(name, mode, factory, errorHandler) {
    var mode_name = "";
    switch(mode) {
      case 0:
        mode_name = "MODE_PRIVATE";
        break;
      case 1:
        mode_name = "MODE_WORLD_READABLE";
        break;
      case 2:
        mode_name = "MODE_WORLD_WRITEABLE";
        break;
      case 8:
        mode_name = "MODE_ENABLE_WRITE_AHEAD_LOGGING";
        break;
      case 16:
        mode_name = "MODE_NO_LOCALIZED_COLLATORS";
        break;
      default:
	    mode_name = "";
    }
    console.log("[*] [Context] openOrCreateDatabase method is called with mode: " + mode_name);
    var retval = this.openOrCreateDatabase(name, mode, factory, errorHandler);
    return retval;
  };
  
  ///////////////////////////////////////////////
  //net.sqlcipher.database.SQLiteDatabase class//
  ///////////////////////////////////////////////
  
  //Open an SQLiteDatabase or create the database file if it doesn't exist
  var netSQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
  netSQLiteDatabase.openOrCreateDatabase.overload('java.io.File', 'java.lang.String', 'net.sqlcipher.database.SQLiteDatabase$CursorFactory').implementation = function(file, password, factory) { 
    console.log("[*] [net.sqlcipher] Database is opened or created with password: " + password);
    var retval = this.openOrCreateDatabase(file, password, factory);
    return retval;
  };
  
  //Execute SQL commands against the database
  netSQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
    console.log("[*] [net.sqlcipher] SQLiteDatabase.exeqSQL method is called with query: " + sql);
    var retval = this.execSQL(sql);
    return retval;
  };
  
  ////////////////////////////////////////////////
  //android.database.sqlite.SQLiteDatabase class//
  ////////////////////////////////////////////////
  
  //This class has methods to create, delete, execute SQL commands and perform database management tasks
  var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
  
  //SQLiteDatabase.openOrCreateDatabase (File file, SQLiteDatabase.CursorFactory factory)
  sqliteDatabase.openOrCreateDatabase.overload('java.io.File', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function(file, factory) {
    console.log("[*] [sqliteDatabase] openOrCreateDatabase method is called with file: " + file);
    var retval = this.openOrCreateDatabase(file, factory);
    return retval;
  };
  
  //SQLiteDatabase openOrCreateDatabase (String path, SQLiteDatabase.CursorFactory factory, DatabaseErrorHandler errorHandler)
  sqliteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'android.database.DatabaseErrorHandler').implementation = function(path, factory, hook) {
    console.log("[*] [sqliteDatabase] openOrCreateDatabase method is called with path: " + path);
    var retval = this.openOrCreateDatabase(path, factory, hook);
    return retval;
  };
  
  //SQLiteDatabase openOrCreateDatabase (String path, SQLiteDatabase.CursorFactory factory)
  sqliteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function(path, factory) {
    console.log("[*] [sqliteDatabase] openOrCreateDatabase method is called with path: " + path);
    var retval = this.openOrCreateDatabase(path, factory);
    return retval;
  };
  
  //SQLiteDatabase.openDatabase (String path, SQLiteDatabase.CursorFactory factory, int flags)
  sqliteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int').implementation = function(path, factory, flags) {
    var flag_name = "";
    switch(flags) {
      case 0:
        flag_name = "OPEN_READWRITE";
        break;
      case 1:
        flag_name = "OPEN_READONLY";
        break;
      case 268435456:
        flag_name = "CREATE_IF_NECESSARY";
        break;
      case 16:
        flag_name = "NO_LOCALIZED_COLLATORS";
        break;
      case 536870912:
        flag_name = "ENABLE_WRITE_AHEAD_LOGGING";
        break;
      default:
	    flag_name = "";
    }
    console.log("[*] [sqliteDatabase] openDatabase method is called with path: " + path + " and flag: " + flag_name);
    var retval = this.openDatabase(path, factory, flags);
    return retval;
  };
  
  //SQLiteDatabase.openDatabase (File path, SQLiteDatabase.OpenParams openParams)
  //sqliteDatabase.openDatabase.overload('java.io.File', 'android.database.sqlite.SQLiteDatabase$OpenParams').implementation = function(path, openParams) {
  //  console.log("[*] [sqliteDatabase] openDatabase method is called with path: " + path);
  //  var retval = this.openDatabase(path, openParams);
  //  return retval;
  //};
  
  //SQLiteDatabase.openDatabase (String path, SQLiteDatabase.CursorFactory factory, int flags, DatabaseErrorHandler errorHandler)
  sqliteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int', 'android.database.DatabaseErrorHandler').implementation = function(path, factory, flags, errorHandler) {
	var flag_name = "";
    switch(flags) {
      case 0:
        flag_name = "OPEN_READWRITE";
        break;
      case 1:
        flag_name = "OPEN_READONLY";
        break;
      case 268435456:
        flag_name = "CREATE_IF_NECESSARY";
        break;
      case 16:
        flag_name = "NO_LOCALIZED_COLLATORS";
        break;
      default:
	    flag_name = "";
    }
    console.log("[*] [sqliteDatabase] openDatabase method is called with path: " + path + " and flag: " + flag_name);
    var retval = this.openDatabase(path, factory, flags, errorHandler);
    return retval;
  };
  
  //SQLiteDatabase.execSQL(String sql)
  sqliteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.exeqSQL method is called with query: " + sql);
    var retval = this.execSQL(sql);
    return retval;
  };
  
  //SQLiteDatabase.execSqL(String, sql, Obj[] bindArgs)
  sqliteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(sql, bindArgs) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.exeqSQL method is called with query: " + sql +  " and arguments: " + bindArgs);
    var execSQLRes = this.execSQL(sql, bindArgs);
    return execSQLRes;
  };

  //SQLiteDatabase.query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
  sqliteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.query method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
    console.log(methodVal + " " + logVal);
    var queryRes = this.query(distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
    return queryRes;
  };

  //SQLiteDatabase.query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
  sqliteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy, limit) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.query method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs;
    console.log(methodVal + " " + logVal);
    var queryRes = this.query(table, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
    return queryRes;
  };

  //SQLiteDatabase.query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
  sqliteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.query method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs;
    console.log(methodVal + " " + logVal);
    var queryRes = this.query(distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal);
    return queryRes;
  };

  //SQLiteDatabase.query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy)
  sqliteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.query method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs;
    console.log(methodVal + " " + logVal);
    var queryRes = this.query(table, columns, selection, selectionArgs, groupBy, having, orderBy);
    return queryRes;
  };
  
  //SQLiteDatabase.queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
  sqliteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(cursorFactory, distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.queryWithFactory method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
    console.log(methodVal + " " + logVal);
    var queryWithFactoryRes = this.queryWithFactory(cursorFactory, distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
    return queryWithFactoryRes;
  };     

  //SQLiteDatabase.queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
  sqliteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(cursorFactory, distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.queryWithFactory method is called";
    var logVal = "Table: " + table + ", selection value: " + selection + ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
    console.log(methodVal + " " + logVal);
    var queryWithFactoryRes = this.queryWithFactory(cursorFactory, distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal);
    return queryWithFactoryRes;
  }; 

  //SQLiteDatabase.rawQuery(String sql, String[] selectionArgs) 
  sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.rawQuery method is called with query: " + sql + " and contentValues: " + selectionArgs);
    var rawQueryRes = this.rawQuery(sql, selectionArgs);
    return rawQueryRes;
  };

  //SQLiteDatabase.rawQuery(String sql, String[] selectionArgs, CancellationSignal cancellationSignal)
  sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal').implementation = function(sql, selectionArgs, cancellationSignal) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.rawQuery method is called with query: " + sql + " and contentValues: " + selectionArgs);
    var rawQueryRes = this.rawQuery(sql, selectionArgs, cancellationSignal);
    return rawQueryRes;
  };

  //SQLiteDatabase.rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable, CancellationSignal cancellationSignal)
  sqliteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(cursorFactory, sql, selectionArgs, editTable, cancellationSignal) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.rawQueryWithFactory method is called with query: " + sql + " and contentValues: " + selectionArgs);
    var rawQueryWithFactoryRes = this.rawQueryWithFactory(cursorFactory, sql, selectionArgs, editTable, cancellationSignal);
    return rawQueryWithFactoryRes;
  };
  
  //SQLiteDatabase.rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable)
  sqliteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(cursorFactory, sql, selectionArgs, editTable) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.rawQueryWithFactory method is called with query: " + sql + " and contentValues: " + selectionArgs);
    var rawQueryWithFactoryRes = this.rawQueryWithFactory(cursorFactory, sql, selectionArgs, editTable);
    return rawQueryWithFactoryRes;
  };

  //SQLiteDatabase.insert(String table, String nullColumnHack, ContentValues values)
  sqliteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.insert method is called. Adding new value: " + values + " into table: " + table);
    var insertValueRes = this.insert(table, nullColumnHack, values);
    return insertValueRes;
  };

  //SQLiteDatabase.insertOrThrow(String table, String nullColumnHack, ContentValues values)
  sqliteDatabase.insertOrThrow.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.insertOrThrow method is called. Adding new value: " + values + " into table: " + table);
    var insertValueRes = this.insertOrThrow(table, nullColumnHack, values);
    return insertValueRes;
  };

  //SQLiteDatabase.insertOrThrow(String table, String nullColumnHack, ContentValues values)
  sqliteDatabase.insertOrThrow.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.insertOrThrow method is called. Adding new value: " + values + " into table: " + table);
    var insertValueRes = this.insertOrThrow(table, nullColumnHack, values);
    return insertValueRes;
  };

  //SQLiteDatabase.insertWithOnConflict(String table, String nullColumnHack, ContentValues initialValues, int conflictAlgorithm)
  sqliteDatabase.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int').implementation = function(table, nullColumnHack, initialValues, conflictAlgorithm) {
    console.log("[*] [sqliteDatabase] SQLiteDatabase.insertWithOnConflict method is called. Adding new value: " + initialValues + " into table: " + table + " and conflictAlgorithm: " + conflictAlgorithm);
    var insertValueRes = this.insertWithOnConflict(table, nullColumnHack, initialValues, conflictAlgorithm);
    return insertValueRes;
  };

  //SQLiteDatabase.update(String table, ContentValues values, String whereClause, String[] whereArgs)
  sqliteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(table, values, whereClause, whereArgs) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.update method is called";
    var logVal = "Update table: " + table + " with where clause: "  + whereClause + " whereArgs:" + whereArgs + " and values to update: " + values;
    console.log(methodVal, logVal);
    var updateRes = this.update(table, values, whereClause, whereArgs);
    return updateRes;
  };

  //SQLiteDatabase.updateWithOnConflict(String table, ContentValues values, String whereClause, String[] whereArgs, int conflictAlgorithm) 
  sqliteDatabase.updateWithOnConflict.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int').implementation = function(table, values, whereClause, whereArgs, conflictAlgorithm) {
    var methodVal = "[*] [sqliteDatabase] SQLiteDatabase.updateWithOnConflict method is called";
    var logVal = "Update table: " + table + " with where clause: "  + whereClause + " whereArgs:" + whereArgs + " values to update: " + values + " and conflictAlgorithm: " + conflictAlgorithm;
    console.log(methodVal, logVal);
    var updateRes = this.updateWithOnConflict(table, values, whereClause, whereArgs, conflictAlgorithm);
    return updateRes;
  };
});