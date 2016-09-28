public final class Sum01 {

  public int foo(int x, final int y) {
    int ss$1 = 1;
    if (x < y)
      x = x + y;
    else
      G = x + y;
    L = G;
    return x + 5;
  }

  //public String  src1() { return "tainted data 1"; }
  //public String  src2() { return "tainted data 2"; }
  //public void  sink(final String x) {}

  private int L;
  private static int  G;
}
