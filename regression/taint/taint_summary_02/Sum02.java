public final class Sum02 {

  private Object localadd(Object l, Object r, boolean choice) { return choice ? l : r; }

  public Object foo(int nondet) {
    Object x = TaintSource.get1();
    Object y = TaintSource.get2();
    if (nondet > 0)
      x = Adder.add(x, y, nondet == 5);
    else
      G = localadd(x, y, nondet == -5);
    L = G;
    return Adder.add(x, new Object(), nondet == 10);
  }

  //public String  src1() { return "tainted data 1"; }
  //public String  src2() { return "tainted data 2"; }
  //public void  sink(final String x) {}

  private Object L;
  private static Object G;
}

class TaintSource {

  public static Object get1() { return new Object(); }
  public static Object get2() { return new Object(); }

}

class Adder {

  public static Object add(Object l, Object r, boolean choice) { return choice ? l : r; }

}
