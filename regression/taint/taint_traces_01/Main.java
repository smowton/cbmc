public class Main {

  public static void branches(int x) {
    if (x > 100)
      --x;
    else
      ++x;
    
    while (x > 0)
      if (x < 50)
       --x;
      else
        x = x - 2;
  }

  public static void XX() {
    int xx = GG;
    GG = xx;
  }

  public static void YY() {
    int yy = GG;
    GG = yy;
  }
  
  public static void ZZ(int zz) {
  }

  public static void foo() {
    int x1 = Main.taint_source_X1_retval();
//    x1 = Main.taint_sanitiser_X1_retval(x1);
    XX();
    GG = x1;
    YY();
    Main.taint_sink_X1_arg_0(x1);
  }

  public static int bar() {
    int x1 = Main.taint_source_X1_retval();
    x1 = baz0(x1);
    bug(x1);
    return x1;
  }

  public static int baz0(int a0) {
    return baz1(a0);
  }

  public static int baz1(int a0) {
    return a0;
  }

  public static void bug(int a0) {
    Main.taint_sink_X1_arg_0(a0);
  }
  
  static int GG;

  public static int taint_source_X1_retval() { return 0; }
  public static int taint_sanitiser_X1_retval(int a0) { return 0; }
  public static void taint_sink_X1_arg_0(int a0) { }
}

