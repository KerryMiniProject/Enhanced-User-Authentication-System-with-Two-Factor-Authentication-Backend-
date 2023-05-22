using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthSA.Model
{

    public class JsonResponseIfUserExists
    {
        public bool? error { get; set; }
        public bool? ifExists { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
    }

    public class JsonResponseOtpEmail
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? email { get; set; }
        public string? Token { get; set; }

    }

    public class JsonFactory
    {
        public JsonResponseOtpEmail generateResponseOtpEmail(sendEmailOtpRequestBody email, string guid)
        {
            JsonResponseOtpEmail response = new JsonResponseOtpEmail();
            response.error = false;
            response.code = "200";
            response.description = "Successful";
            response.display = "Otp has been sent";
            response.email = email.Email;
            response.Token = guid;
            return response;
        }

        public JsonResponseOtp generateResponseOtpPhone(JsonResponseFromKerry respKerry)
        {
            JsonResponseOtp jsonResponse = new JsonResponseOtp();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successfully";
            jsonResponse.token = respKerry.Token;
            jsonResponse.reference = respKerry.Reference;
            return jsonResponse;
        }

        public JsonResponseOtp generateResponseOtpPhoneVerification(OtpVerificationJsonResponseKerry respKerry)
        {
            JsonResponseOtp jsonResponse = new JsonResponseOtp();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successfully";
            jsonResponse.token = respKerry.Token;
            jsonResponse.reference = respKerry.Reference;
            return jsonResponse;
        }

        public JsonResponseIfUserExists generateResponseUserExist(bool ifExist)
        {
            JsonResponseIfUserExists jsonResponse = new JsonResponseIfUserExists();
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.error = false;
            jsonResponse.ifExists = ifExist;
            if (ifExist)
            {
                jsonResponse.display = "User exists";
                
            }
            else
            {
                jsonResponse.display = "User does not exist";
            }
            return jsonResponse;
        }

        public JsonResponseFactory generateBadJson(string? error)
        {
            JsonResponseFactory jsonResponse = new JsonResponseFactory();
            jsonResponse.error = true;
            jsonResponse.code = "401";
            jsonResponse.description = "Unauthorized";
            jsonResponse.display = error;
            return jsonResponse;
        }

        public JsonResponseOtpPhoneVerification generateSuccessfulOtpPhoneVerificicationResponse(OtpVerificationJsonResponseKerry respKerry)
        {
            JsonResponseOtpPhoneVerification jsonResponse = new JsonResponseOtpPhoneVerification();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successfully";
            jsonResponse.token = respKerry.Token;
            jsonResponse.reference = respKerry.Reference;
            jsonResponse.otp = respKerry.Otp;
            jsonResponse.recipient = respKerry.Recipient;
            jsonResponse.isValidOtp = respKerry.IsValidOtp;
            return jsonResponse;
        }


        public JsonResponseOtpEmailVerification generateSuccessfulOtpEmailVerificicationResponse(OtpEmailVerificationRequestBody requestBody, bool ifExists)
        {
            JsonResponseOtpEmailVerification jsonResponse = new JsonResponseOtpEmailVerification();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = (ifExists) ? "Successfully": "Verification Failed";
            jsonResponse.token = requestBody.Token;
            jsonResponse.recipient = requestBody.Email;
            jsonResponse.isValidOtp = ifExists;

            return jsonResponse;
        }


    }


    public class JsonResponseFactory
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }

    }


    public class JsonResponseFromKerry
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
        public string? InitiateSource { get; set; }
        public string? Module { get; set; }
        public string? Recipient { get; set; }
        public string? RecipientType { get; set; }
        public DateTime? ExpiryDate { get; set; }
        public int? ExpiryDateTimestamp { get; set; }
        public DateTime? CreatedDate { get; set; }
        public int? CreatedDateTimestamp { get; set; }

    }

    public class JsonResponseOtp
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? token { get; set; }
        public string? reference { get; set; }

    }

    public class JsonResponseOtpPhoneVerification
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? token { get; set; }
        public string? reference { get; set; }
        public string? otp { get; set; }
        public string? recipient { get; set; }
        public bool? isValidOtp { get; set; }
    }

    public class JsonResponseOtpEmailVerification
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? token { get; set; }
        public string? recipient { get; set; }
        public bool? isValidOtp { get; set; }
    }

    public class OtpVerificationJsonResponseKerry
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
        public string? Otp { get; set; }
        public string? Recipient { get; set; }
        public bool? IsValidOtp { get; set; }
    }

 


}
