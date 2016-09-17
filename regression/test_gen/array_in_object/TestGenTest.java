
public class TestGenTest {

  public static void test(B input) {

    int[] got = input.got;
    A[] got2 = input.got2;
    long[] got3 = input.got3;
    assert(!(input != null && got != null && got.length == 2 && got[0] == 1 && got[1] == 2 && got2 != null && got2.length == 2 && got2[0] != null && got2[1] != null && got2[0].x == 3 && got2[1].x == 4 && got3 != null && got3.length == 1 && got3[0] == 100));

  }

}

class B {

  public int[] got;
  public A[] got2;
  public long[] got3;

}

class A {

  int x;

}
