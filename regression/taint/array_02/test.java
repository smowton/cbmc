public class test {

  public static int main(int t1) {

    int[] fresh = new int[10];
    modify(fresh,t1);
    return fresh[5];

  }

  public static void modify(int[] m, int insert) {
   m[5] = insert;
  }

}
