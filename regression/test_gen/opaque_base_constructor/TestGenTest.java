public class TestGenTest {
  public static void test() {
    Known o = new Known();
    assert(!(o != null && o.x == 1 && o.y == 2));
  }
}

class Opaque {
  public int x;
  public Opaque() { x = 1; }
}

class Known extends Opaque {
  public int y;
  public Known() { y = 2; }
}

