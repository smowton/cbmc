public class caller {

  public static int main(int t1, int t2) {

    LL node1 = new LL();
    LL node2 = new LL();
    LL node3 = new LL();
    node3.tail = node2;
    node2.tail = node1;
    callee.modify_list(node3,t1,t2);
    return node2.val;

  }

}

class LL {

  int val;
  LL tail;

}
