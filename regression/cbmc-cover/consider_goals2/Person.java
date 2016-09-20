public class Person {

  private int age;

  //public method to get the age variable
  public int getAge(){
       return this.age;
  }

  //public method to set the age variable
  public void setAge(int age){
       this.age = age;
  }

  public static void main(String[] args) {
    Person p = new Person();
    p.setAge(10);
    int x = p.getAge();
  }
}

