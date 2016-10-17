public class Person {

  private int age;

  //public method to get the age variable
  public int getAge(){
       return this.age;
  }

  //public method to set the age variable
  public void setAge(int age){
       int smokedCigarettes = 3;
       this.age = age;
   
       double averageCigarettesPerYear = smokedCigarettes * 1.0 / age;

       if(averageCigarettesPerYear >= 7300.0) {
            assert false;
       }
  }

  public static void main(String[] args) {
    Person p = new Person();
    p.setAge(10);
    int x = p.getAge();
  }
}

