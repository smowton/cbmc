public class TestGenTest {
  public static void test() {
    Known o = new Known();
    assert(!(o != null && o.x() == 4 && o.y() == 8));
  }
}

class Opaque {
  public int x() { return 0; };
  public int y() { return 0; };
}

class Known extends Opaque {
  public int x() { return super.x() + 1; }
  public int y() { return super.y() + 2; }
}

