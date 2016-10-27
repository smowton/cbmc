public class TestGenTest {
  public static void test() {
    Known o = new Known();
    assert(!(o != null && o.x == 1 && o.y == 2 && o.z == 3));
  }
}

class Opaque {
  public int x;
  public Opaque() { x = 1; }
}

class Known2 extends Opaque {
  public int z;
  public Known2() { z = 3; }
}

class Known extends Known2 {
  public int y;
  public Known() { y = 2; }
}

