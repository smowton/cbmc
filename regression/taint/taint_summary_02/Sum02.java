public final class Sum02 {

  private int localadd(int l, int r) { return l + r; }

  public int foo(int nondet) {
    int x = TaintSource.get1();
    int y = TaintSource.get2();
    if (nondet > 0)
      x = Adder.add(x, y);
    else
      G = localadd(x, y);
    L = G;
    return Adder.add(x, 5);
  }

  private int L;
  private static int G;
}

class TaintSource {

  public static int get1() { return 0; }
  public static int get2() { return 0; }

}

class Adder {

  public static int add(int l, int r) { return l + r; }

}
