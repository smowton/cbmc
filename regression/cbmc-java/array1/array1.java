class array1
{
  public static void main(String[] args)
  {
    int size=10;
    int int_array[]=new int[10];

    int any_index = new java.util.Random().nextInt();
    if (any_index < 0 || any_index >= size) return;
    assert int_array[any_index] == 0;
    
    for(int i=0; i<size; i++)
      int_array[i]=i;

    assert int_array[any_index] == any_index;

    what_not what_not_array[]=new what_not[size];
    
    assert what_not_array.length == size;
  }
}

