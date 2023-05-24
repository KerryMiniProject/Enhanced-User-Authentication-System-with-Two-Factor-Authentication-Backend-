namespace AuthSA.Model
{
    public class OtpPhoneVerificationRequestBody
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
        public string? Otp { get; set; }
    }

    public class OtpEmailVerificationRequestBody
    {
        public string? Token { get; set; }
        public string? Email { get; set; }
        public string? Otp { get; set; }
    }


    public class sendPhoneOtpRequestBody
    {
        public string? PhoneNo { get; set; }
    }

    public class sendEmailOtpRequestBody
    {
        public string? Email { get; set; }
    }

    public class checkUserExistsRequestBody
    {
        public string? PhoneNo { get; set; }
        public string? Email { get; set; }

    }

    public class ResetPasswordRequestBody
    {
        public string? PhoneNo { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }

    }

    public class GenerateAccessTokenRequestBody
    {
        public string? RefreshToken { get; set; }

    }
}
