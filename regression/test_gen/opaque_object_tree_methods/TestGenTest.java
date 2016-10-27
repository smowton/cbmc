public class TestGenTest {
  public static void test() {
    Opaque o = new Opaque();
    assert(!(o != null && o.y != null && o.x == 1 && o.y.x == 2 && o.y.get() == 3));
  }
}

class Opaque {
  public int x;
  public Opaque2 y;
}

class Opaque2 {
  public int x;
  public int get() { return 0; }
}
