﻿

namespace AuthSA.Model
{
    public class JsonFactory
    {
        public JsonResponseResetPassword? generateResponseResetPassword(string message = null, string code=null)
        {
            JsonResponseResetPassword response = new JsonResponseResetPassword();
            response.code = (code != null) ? code: "200";
            response.error = (response.code.Equals("200")) ? false : true;
            response.description = (response.code != null) ? "Successful" : "Failed";
            response.display = (message != null) ? message : "Reset Password Successful";
            return response;
        }

        public JsonResponseSignUp? generateResponseSignUp()
        {
            JsonResponseSignUp response = new JsonResponseSignUp();
            response.error = false;
            response.code = "200";
            response.description = "Successful";
            response.display = "Sign up successful";
            return response;

        }

        public JsonResponseSignUp? generateResponseLogout()
        {
            JsonResponseSignUp response = new JsonResponseSignUp();
            response.error = false;
            response.code = "200";
            response.description = "Successful";
            response.display = "Logout successful";
            return response;

        }

        public JsonResponseCheckAccessTokenExpiry? generateResponseCheckExpiry(bool expired)
        {
            JsonResponseCheckAccessTokenExpiry response = new JsonResponseCheckAccessTokenExpiry();
            response.error = false;
            response.code = "200";
            response.description = "Successful";
            response.display = (expired)?"Access Token has expired": "Access Token has not expired";
            response.isExpired = expired;
            return response;
        }
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


        public JsonResponseOtpEmailVerification generateSuccessfulOtpEmailVerificicationResponse(OtpEmailVerificationRequestBody requestBody, bool ifExists, string email)
        {
            JsonResponseOtpEmailVerification jsonResponse = new JsonResponseOtpEmailVerification();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = (ifExists) ? "Successfully": "Verification Failed";
            jsonResponse.token = requestBody.Token;
            jsonResponse.recipient = email;
            jsonResponse.isValidOtp = ifExists;

            return jsonResponse;
        }


        public JsonResponseQrCodeLogin generateSuccessfulQrLoginResponse()
        {
            JsonResponseQrCodeLogin jsonResponse = new JsonResponseQrCodeLogin();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successful";

            return jsonResponse;
        }

        public JsonResponseGetEmail generateSuccessfulGetEmailResponse(string email)
        {
            JsonResponseGetEmail jsonResponse = new JsonResponseGetEmail();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successful";
            jsonResponse.email = email;

            return jsonResponse;
        }

        public JsonResponseCheckCredentials generateSuccessfulCheckCredentials(bool isCorrect)
        {
            JsonResponseCheckCredentials jsonResponse = new JsonResponseCheckCredentials();
            jsonResponse.error = !isCorrect;
            jsonResponse.code = (isCorrect) ? "200":"401";
            jsonResponse.description = "OK";
            jsonResponse.display = (isCorrect) ? "Successful" : "Wrong password";
            jsonResponse.isCorrect = isCorrect;
            return jsonResponse;
        }

        public JsonResponseGetUserDetails generateGetUserDetailsResponse(bool isError, UserInfo userInfo)
        {
            JsonResponseGetUserDetails jsonResponse = new JsonResponseGetUserDetails();
            jsonResponse.error = isError;
            jsonResponse.code = (isError) ? "401" : "200";
            jsonResponse.description = "OK";
            jsonResponse.display = (isError) ? "Failure" : "Successful";
            jsonResponse.userInfo = userInfo;
            return jsonResponse;
        }

        public JsonResponseGetPhoneNo generateSuccessfulGetPhoneNoResponse(string phoneNo)
        {
            JsonResponseGetPhoneNo jsonResponse = new JsonResponseGetPhoneNo();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successful";
            jsonResponse.phoneNo = phoneNo;

            return jsonResponse;
        }

    }

    public class JsonResponseCheckCredentials
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public bool? isCorrect { get; set; }
    }

    public class JsonResponseIfUserExists
    {
        public bool? error { get; set; }
        public bool? ifExists { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
    }

    public class JsonResponseGetUserDetails
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public UserInfo? userInfo { get; set; }
    }

    public class JsonResponseSignUp
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
    }

    public class JsonResponseGetEmail
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? email { get; set; }
    }

    public class JsonResponseGetPhoneNo
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public string? phoneNo { get; set; }
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

    public class JsonResponseResetPassword
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
    }

    public class JsonResponseCheckAccessTokenExpiry
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }
        public bool? isExpired { get; set; }
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

    public class JsonResponseQrCodeLogin
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }

    }





}
