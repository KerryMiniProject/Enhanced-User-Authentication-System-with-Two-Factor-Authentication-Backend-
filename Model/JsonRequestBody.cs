namespace AuthSA.Model
{
    public class OtpVerificationRequestBody
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
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
}
