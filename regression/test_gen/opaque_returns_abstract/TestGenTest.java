public class TestGenTest {
  public static void test() {
    Returned r = Opaque.x();
    assert(!(r != null && r.x() == 1 && r.y() == 5));
  }
}

class Opaque {
  public static Returned x() { return new ReturnedImpl(); }
}

abstract class Returned {
  public abstract int x();
  public int y() { return 5; }
}

class ReturnedImpl extends Returned {
  public int x() { return 0; }
}

