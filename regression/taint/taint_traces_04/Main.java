public class Main {

  public OtherBase1  foo() {
    OtherBase1 ptr = new Other();
    return ptr;
  }
  
  public void  baz0() {
    OtherBase1 ptr = foo();
    int i = ptr.someMethod();
    taint_sink_X1_arg_0(i);
  }

  public void  baz1() {
    Other ptr = new Other();
    int i = ptr.someMethod();
    taint_sink_X1_arg_0(i);
  }

  public void  baz2(Other ptr) {
    int i = ptr.someMethod();
    taint_sink_X1_arg_0(i);
  }

//  static int GG;

//  public static int taint_source_X1_retval() { return 0; }
  public static int taint_sanitiser_X1_retval(int a0) { return 0; }
  public static void taint_sink_X1_arg_0(int a0) { }
}

