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

    public class ForgetPasswordPhoneRequestBody
    {
        public string? PhoneNo { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public OtpPhoneVerificationRequestBody? phoneVerificationRequestBody { get; set; }

    }

    public class ForgetPasswordEmailRequestBody
    {
        public string? PhoneNo { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public OtpEmailVerificationRequestBody? emailVerificationRequestBody { get; set; }

    }

    public class SignupRequestBody
    {
        public User? user { get; set; }
        public OtpPhoneVerificationRequestBody? phoneVerificationRequestBody { get; set; }
        public OtpEmailVerificationRequestBody? emailVerificationRequestBody { get; set; }
    }


    public class GenerateAccessTokenRequestBody
    {
        public string? RefreshToken { get; set; }
        public string?AccessToken { get; set; }

    }
}
