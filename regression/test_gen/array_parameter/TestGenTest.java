
public class TestGenTest {

  public static void test(int[] got, A[] got2, long[] got3) {

    assert(!(got != null && got.length == 2 && got[0] == 1 && got[1] == 2 && got2 != null && got2.length == 2 && got2[0] != null && got2[1] != null && got2[0].x == 3 && got2[1].x == 4 && got3 != null && got3.length == 1 && got3[0] == 100));

  }

}

class A {

  int x;

}
