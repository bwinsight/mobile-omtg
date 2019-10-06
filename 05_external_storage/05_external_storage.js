function bytes2ascii(array) {
  var result = "";
  for(var i = 0; i < array.length; ++i) {
    result+= (String.fromCharCode(array[i]));
  }
  return result;
}

Java.perform(function() {
  //Load classes that operate on files into variables
  var File = {
    init: [
      Java.use("java.io.File").$init.overload("java.lang.String"),
      Java.use("java.io.File").$init.overload("java.lang.String", "java.lang.String")
    ]
  };
  var FileInputStream = {
    init: [
      Java.use("java.io.FileInputStream").$init.overload("java.io.File")
    ],
    read: [
      Java.use("java.io.FileInputStream").read.overload(),
      Java.use("java.io.FileInputStream").read.overload("[B", "int", "int")
    ],
  };
  var FileOuputStream = {
    init: [
      Java.use("java.io.FileOutputStream").$init.overload("java.io.File"),
      Java.use("java.io.FileOutputStream").$init.overload("java.io.File", "boolean"),
      Java.use("java.io.FileOutputStream").$init.overload("java.io.FileDescriptor"),
      Java.use("java.io.FileOutputStream").$init.overload("java.lang.String"),
      Java.use("java.io.FileOutputStream").$init.overload("java.lang.String", "boolean")
    ],
    write: [
      Java.use("java.io.FileOutputStream").write.overload("int"),
      Java.use("java.io.FileOutputStream").write.overload("[B", "int", "int")
    ],
  };

  //Arrays for file descriptor, path, file
    var TraceFD = {};
    var TraceFS = {};
    var TraceFile = {};

  //Hook the relevant file activity methods
  File.init[0].implementation = function(a0) {
    console.log("[*] New file instance (" + a0 + ")");
    var ret = File.init[0].call(this, a0);
    var f = Java.cast(this, Java.use("java.io.File"));
    TraceFile["f" + this.hashCode()] = a0;
    return ret;
  }
  File.init[1].implementation = function(a0, a1) {
    console.log("[*] New file instance (" + a0 + "/" + a1 + ")");
    var ret = File.init[1].call(this, a0, a1);
    var f = Java.cast(this, Java.use("java.io.File"));
    TraceFile["f" + this.hashCode()] = a0 + "/" + a1;
    return ret;
  }
  FileInputStream.init[0].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null) {
      var p = file.getAbsolutePath();
      if (p !== null)
        fname = TraceFile["f" + file.hashCode()] = p;
    }
    if (fname == null)
      fname = "[unknow]"
    console.log("[*] New input stream from file (" + fname + "): ");
    var fis = FileInputStream.init[0].call(this, a0)
    var f = Java.cast(this, Java.use("java.io.FileInputStream"));
    TraceFS["fd" + this.hashCode()] = fname;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = fname;
    return fis;
  }
  FileInputStream.read[0].implementation = function() {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
      fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] Read from file, offset (" + fname + "):\n" +
    console.log(fname));
    return FileInputStream.read[0].call(this);
  }
  FileInputStream.read[1].implementation = function(a0, a1, a2) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
      fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    var b = Java.array('byte', a0);
    console.log("[*] Read from file, offset, length (" + fname + "," + a1 + "," + a2 + ")\n" +
    console.log(fname, b));
    return FileInputStream.read[1].call(this, a0, a1, a2);
  }
  FileOuputStream.init[0].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null)
      fname = "[unknow]<File:" + file.hashCode() + ">";
    console.log("[*] New output stream to file (" + fname + "): ");
    var fis = FileOuputStream.init[0].call(this, a0);
    TraceFS["fd" + this.hashCode()] = fname;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = fname;
    return fis;
  }
  FileOuputStream.init[1].implementation = function(a0) {
    var file = Java.cast(a0, Java.use("java.io.File"));
    var fname = TraceFile["f" + file.hashCode()];
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] New output stream to file (" + fname + "): \n");
    var fis = FileOuputStream.init[1].call(this, a0);
    return fis;
  }
  FileOuputStream.init[2].implementation = function(a0) {
    var fd = Java.cast(a0, Java.use("java.io.FileDescriptor"));
    var fname = TraceFD["fd" + fd.hashCode()];
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] New output stream to FileDescriptor (" + fname + "): \n");
    var fis = FileOuputStream.init[2].call(this, a0)
    TraceFS["fd" + this.hashCode()] = fname;
    return fis;
  }
  FileOuputStream.init[3].implementation = function(a0) {
    console.log("[*] New output stream to file (str=" + a0 + "): \n");
    var fis = FileOuputStream.init[3].call(this, a0)
    TraceFS["fd" + this.hashCode()] = a0;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = a0;
    return fis;
  }
  FileOuputStream.init[4].implementation = function(a0) {
    console.log("[*] New output stream to file (str=" + a0 + ",bool): \n");
    var fis = FileOuputStream.init[4].call(this, a0)
    TraceFS["fd" + this.hashCode()] = a0;
    var fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    TraceFD["fd" + fd.hashCode()] = a0;
    return fis;
  }
  FileOuputStream.write[0].implementation = function(a0) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    fname = TraceFD["fd" + fd.hashCode()]
    }
    if (fname == null)
      fname = "[unknow]";
    console.log("[*] Written into file (" + fname + "), output stream: " + a0);
    return FileOuputStream.write[0].call(this, a0);
  }
  FileOuputStream.write[1].implementation = function(a0, a1, a2) {
    var fname = TraceFS["fd" + this.hashCode()];
    var fd = null;
    if (fname == null) {
      fd = Java.cast(this.getFD(), Java.use("java.io.FileDescriptor"));
    fname = TraceFD["fd" + fd.hashCode()]
    if (fname == null)
      fname = "[unknow], fd=" + this.hashCode();
    }
    console.log("[*] Written " + a2 + " bytes from " + a1 + " offset into file (" + fname + "), output stream: " + bytes2ascii(a0));
    return FileOuputStream.write[1].call(this, a0, a1, a2);
  }
});