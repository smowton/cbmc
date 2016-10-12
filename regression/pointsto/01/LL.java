public final class LL {

  public static void change_second(LL param) {
    final LL local = param;
    final LL local2 = local.next;
    local2.next = new LL();
  }
/*
  public static void change_nth(LL param) {
    LL victim = param;
    while (victim.value != 0)
      victim = victim.next;
    victim.next = new LL();
  }
*/
  private int value;
  private LL next;
}

