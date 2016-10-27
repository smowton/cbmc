public class TestGenTest {
   public static void test() {
    Opaque o1 = Opaque.get();
    Opaque o2 = Opaque.get();
    assert(!(o1 != null && o2 != null && o1.x == 1 && o2.x == 2));
  }
}

class Opaque {
  public int x;
  public static Opaque get() { return new Opaque(); }
}
