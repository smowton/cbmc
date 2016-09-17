
public class TestGenTest {

  public static void test(A input) {

    assert(!(input != null &&
             input.arr1 != null &&
             input.arr2 != null &&
             input.arr1.length == 2 &&
             input.arr1[0] == 10 &&
             input.arr1[1] == 20 &&
             input.arr2.length == 2 &&
             input.arr2[0] != null &&
             input.arr2[1] != null &&
             input.arr2[0].x == 30 &&
             input.arr2[0].y == 40 &&
             input.arr2[1].x == 50 &&
             input.arr2[1].y == 60));

  }

}

class A {

  int[] arr1;
  B[] arr2;

}

class B {

  int x;
  int y;

}
