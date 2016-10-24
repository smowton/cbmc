public class Main {

  public static void foo() {
    int x1 = Main.taint_source_X1_retval();
    Main.taint_sink_X1_arg_0(x1);
  }

  public static int bar() {
    int x1 = Main.taint_source_X1_retval();
    x1 = baz0(x1);
    bug(x1);
    return x1;
  }

  public static int baz0(int a0) {
    int local = a0;
    return baz1(local);
  }

  public static int baz1(int a0) {
    return a0;
  }

  public static void bug(int a0) {
    a0=a0;
    Main.taint_sink_X1_arg_0(a0);
  }

  public static int taint_source_X1_retval() { return 0; }
  public static int taint_sanitiser_X1_retval(int a0) { return 0; }
  public static void taint_sink_X1_arg_0(int a0) { }
}

