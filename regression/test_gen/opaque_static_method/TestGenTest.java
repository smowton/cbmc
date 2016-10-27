public class TestGenTest {
   public static void test() {
    assert(!(Opaque.get() == 1 && Opaque.get() == 2));
  }
}

class Opaque {
  public static int get() { return 0; }
}
