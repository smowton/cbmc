import java.io.InputStream;

public class TaintedInputStream extends InputStream {
  public int read() {
    return TaintSource.get_tainted_int();
  }
  public int read(byte[] data, int x, int length) {
    data[x] = (byte)TaintSource.get_tainted_int();
    return 1;
  }
}

