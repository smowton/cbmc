import java.io.InputStream;

public class FileItem {
  public InputStream getInputStream()	{
    return new TaintedInputStream();
	}  
}

