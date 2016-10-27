public class TestGenTest {
   public static void test() {
    Opaque factory = new Opaque();
    Opaque o1 = factory.get();
    Opaque o2 = factory.get();
    assert(!(o1 != null && o2 != null && o1.x == 1 && o2.x == 2));
  }
}

class Opaque {
  public int x;
  public Opaque get() { return new Opaque(); }
}
