public class TestGenTest {
   public static void test() {
    assert(!((new Opaque()).get() == 1 && (new Opaque()).get() == 2));
  }
}

class Opaque {
  public int get() { return 0; }
}
