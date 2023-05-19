namespace AuthSA.Model
{

    public class Users
    {
        public User[]? UserList { get; set; }
    }

    public class User
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? PhoneNo { get; set; }
        public string? Password { get; set; }
    }

    public class OtpSendEmailResponse
    {
        public string? Guid { get; set; }
        public string? Email { get; set; }
    }

}
