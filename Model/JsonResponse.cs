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
        public JsonResponseOtpEmail generateResponseOtpEmail(User user, string guid)
        {
            JsonResponseOtpEmail response = new JsonResponseOtpEmail();
            response.error = false;
            response.code = "200";
            response.description = "Successful";
            response.display = "Otp has been sent";
            response.email = user.Email;
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

        public JsonResponse generateBadJson(string? error)
        {
            JsonResponse jsonResponse = new JsonResponse();
            jsonResponse.error = true;
            jsonResponse.code = "401";
            jsonResponse.description = "Unauthorized";
            jsonResponse.display = error;
            return jsonResponse;
        }

        
    }


    public class JsonResponse
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public string? display { get; set; }




        public JsonResponse success(string? displayEn = null, string? displayTh = null)
        {
            JsonResponse jsonResponse = new JsonResponse();
            Display display = new Display();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            display.th = (displayTh == null) ? "สำเร็จ" : displayTh;
            display.en = (displayEn == null) ? "Successfully" : displayEn;
            jsonResponse.description = "OK";
            jsonResponse.display = "Successfully";
            return jsonResponse;
        }

        //public JsonResponseOtp successOtp(JsonResponseFromKerry respKerry)
        //{
        //    JsonResponseOtp jsonResponse = new JsonResponseOtp();
        //    Display display = new Display();
        //    jsonResponse.error = false;
        //    jsonResponse.code = "200";
        //    display.th = "สำเร็จ";
        //    display.en = "Successfully";
        //    jsonResponse.description = "OK";
        //    jsonResponse.display = display;
        //    jsonResponse.token = respKerry.Token;
        //    jsonResponse.reference = respKerry.Reference;

        //    return jsonResponse;
        //}

        public JsonResponseOtpVerification successOtp(OtpVerificationJsonResponseKerry respKerry)
        {
            JsonResponseOtpVerification jsonResponse = new JsonResponseOtpVerification();
            Display display = new Display();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            display.th = "สำเร็จ";
            display.en = "Successfully";
            jsonResponse.description = "OK";
            jsonResponse.display = display;
            jsonResponse.responseOtpVerification = respKerry;
            return jsonResponse;
        }



        public JsonResponse respOtp()
        {
            JsonResponse jsonResponse = new JsonResponse();
            Display display = new Display();
            jsonResponse.error = false;
            jsonResponse.code = "200";
            display.th = "สำเร็จ";
            display.en = "Successfully";
            jsonResponse.description = "OK";
            jsonResponse.display = "Successfully";
            return jsonResponse;
        }

        public JsonResponse badAuth(string? displayEn = null, string? displayTh = null)
        {
            JsonResponse jsonResponse = new JsonResponse();
            Display display = new Display();
            jsonResponse.error = error;
            jsonResponse.code = "401";
            jsonResponse.description = "Unauthorized";
            display.th = (displayTh == null) ? "ไม่ได้รับอนุญำต" : displayTh;
            display.en = (displayEn == null) ? "Unauthorized" : displayEn;
            jsonResponse.display = "Unauthorized";
            return jsonResponse;
        }

        //public JsonResponseOtp badAuthOtp()
        //{
        //    JsonResponseOtp jsonResponse = new JsonResponseOtp();
        //    Display display = new Display();
        //    jsonResponse.error = error;
        //    jsonResponse.code = "401";
        //    jsonResponse.description = "Unauthorized";
        //    display.th = "ไม่ได้รับอนุญำต";
        //    display.en = "Unauthorized";
        //    jsonResponse.display = display;
        //    return jsonResponse;
        //}






    }
    public class Display
    {
        public string? th { get; set; }
        public string? en { get; set; }
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
    //otp response and req

    public class JsonResponseOtpVerification
    {
        public bool? error { get; set; }
        public string? code { get; set; }
        public string? description { get; set; }
        public Display? display { get; set; }
        public OtpVerificationJsonResponseKerry? responseOtpVerification { get; set; }


    }

    public class OtpVerificationJsonResponseKerry
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
        public string? Otp { get; set; }
        public string? Recipient { get; set; }
        public bool? IsValidOtp { get; set; }
    }

    public class OtpVerificationRequestBody
    {
        public string? Token { get; set; }
        public string? Reference { get; set; }
        public string? Otp { get; set; }
    }


}
