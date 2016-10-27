public class TestGenTest {
   public static void test() {
    Opaque o = new Opaque();
    assert(!(o.get() == 1 && o.get() == 2));
  }
}

class Opaque {
  public int get() { return 0; }
}
