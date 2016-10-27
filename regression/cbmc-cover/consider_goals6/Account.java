
public class Account{
    
    public static void main(String[] args){
        String name = "Neil Peart";
        int ID=2112; 
        double salary = 1000000;
        
        Employee employee = new Employee(name, ID, salary);
        
        employee.setName(name);
        employee.setID(ID);
        employee.setSalary(salary);
        
        employee.display();
    }
}

