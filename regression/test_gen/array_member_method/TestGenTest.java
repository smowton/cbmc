
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
             input.arr2[0].get() == 30 &&
             input.arr2[0].get() == 40 &&
             input.arr2[1].get() == 50 &&
             input.arr2[1].get() == 60));

  }

}

class A {

  int[] arr1;
  B[] arr2;

}

class B {

  public int get() { return 0; }

}
