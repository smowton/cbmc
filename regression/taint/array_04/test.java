public class test {

  public static int main(int t1) {

    A[] fresh = new A[2];
    fresh[0] = new A();
    fresh[1] = new A();
    fresh[0].x=t1;
    return readarray(fresh);

  }

  public static int readarray(A[] as) {
   return as[1].x;
  }

}

class A {

  int x;

}
