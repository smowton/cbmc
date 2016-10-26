class Local {

  public Local() {
    this.LL = 400;
  }

  public int baz(int aa) {
    LL = aa;
    if (aa < 350)
      return LL + GG;
    return 2000;
  }

  private int LL;
  private static int  GG = 300;
}


public final class Sum01 {

  public Sum01() {
    this.L = 200;
  }

  public void  Y(Object oo) {
    do { } while (G < 0);
  }

  public Object  X(Object o) {
    Y(o);
    return o;
  }

  public int bar(int a) {
    L = a;
    if (a < 150)
      return L + G;
    return 1000;
  }

  public int foo(int x, final int y, final Local local) {
    int ss$1 = 1;
    if (x < y)
      x = bar(x) + y;
    else
      G = local.baz(x) + y;
    L = G;
    return x + 5;
  }

  public static void main() {
    Sum01 s = new Sum01();
    Local l = new Local();
    s.foo(G,50,l);
  }

  private int L;
  private static int  G = 100;
}
