
public class taintin {

  public static int f(int t1, int t2) {

    LL node1 = new LL();
    LL node2 = new LL();
    LL node3 = new LL();
    node1.val=t1;
    node1.tail=node2;
    node2.val=t2;
    node2.tail=node3;
    node3.val=100;
    return taintrx.process(node1);

  }

}

class LL {
  int val;
  LL tail;
}
