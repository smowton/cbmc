public class test {

  int test(int incoming_taint, int unknown) {

    LL head1 = new LL();
    LL head2 = new LL();
    LL tail = new LL();
    head1.val = incoming_taint;
    if(unknown == 10)
      tail.tail = head1;
    else
      tail.tail = head2;
    return tail.tail.val;

  }

}

class LL {

  int val;
  LL tail;

}

