
public class taintrx {

  public static int process(LL l) {

    LL toproc = l;
    while(toproc.val!=50 && toproc.tail!=null)
      toproc=toproc.tail;
    return toproc.val;

  }

}
