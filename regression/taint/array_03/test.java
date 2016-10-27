public class test {

  public static int main(int t1) {

    A[] fresh = new A[2];
    fresh[0] = new A();
    fresh[1] = new A();
    modify(fresh,t1);
    return fresh[0].x;

  }

  public static void modify(A[] as, int insert) {
   as[1].x = insert;
  }

}

class A {

  int x;

}
