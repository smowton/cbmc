public class TestGenTest {
  public static void test() {
    Returned r = Opaque.x();
    assert(!(r != null && r.x() == 1));
  }
}

class Opaque {
  public static Returned x() { return new ReturnedImpl(); }
}

interface Returned {
  public int x();
}

class ReturnedImpl implements Returned {
  public int x() { return 0; } 
}

