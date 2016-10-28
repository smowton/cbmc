// string literal should not produce taint
class Test {

  // entry functions

  public static void start() {
    String s = "xyz";
    taint_sink_01(s);
  }

  // other functions
  
  // ...

  // taint functions

  public static String taint_source_01() {
    return "...";
  }

  public static void taint_sink_01(String s) {}

  public static String taint_sanitize_01(String s) {
    return s;
  }
}

