public class TestGenTest {
   public static void test() {
    Opaque o = new Opaque();
    assert(!(o.x == 1 && o.y == 2));
  }
}

class Opaque {
  public int x;
  public int y;
}
