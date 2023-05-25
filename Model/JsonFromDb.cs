namespace AuthSA.Model
{
    public class JsonFromDb
    {

    }


    public class UserDetails
    {
        public UserEmailPhone[]? userEmailPhones { get; set; }
    }

    public class UserEmailPhone
    {
        public string? Email { get; set; }
        public string? Phone_No { get; set; }
    }

}
