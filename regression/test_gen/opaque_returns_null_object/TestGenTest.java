public class TestGenTest {
   public static void test() {
    Opaque o1 = Opaque.get();
    assert(!(Opaque.get() == null && o1 != null && o1.x == 2));
  }
}

class Opaque {
  public int x;
  public static Opaque get() { return new Opaque(); }
}
