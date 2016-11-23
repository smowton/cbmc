// taint flow from callee into callee
class Test {

  // entry functions

  public static void start() {
    int v1;
    int v2;

    v1 = func1(); // taint source
    v2 = func2(v1); // taint sanitizer
    func3(v2); // taint sink
  }

  // other functions
  
  public static int func1() {
    int v;
    v = taint_source_01();
    return v;
  }

  public static int func2(int a) {
    int v;
    v = taint_sanitize_01(a);
    return v;
  }

  public static void func3(int a) {
    taint_sink_01(a);
  }  

  // taint functions

  public static int taint_source_01() {
    return 0;
  }

  public static void taint_sink_01(int i) {}

  public static int taint_sanitize_01(int i) {
    return i;
  }
}

