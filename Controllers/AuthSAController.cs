using AuthSA.Model;
using AuthSA.Util;
using Microsoft.AspNetCore.Mvc;




namespace AuthSA.Controllers
{
    public class AuthSAController : Controller
    {
        PasswordHasher passwordHasher = new PasswordHasher();
        OTPProvider otpProvider = new OTPProvider();
        Database db = new Database();
        Procedure procedure = new Procedure();
        //Auth auth = new Auth();

        //[HttpPost("/auth/sign-up")]
        //public IActionResult SignUp([FromBody] User user)
        //{
        //    return Ok(auth.SignUp(user));
        //}



        [HttpPost("/auth/send-otp-to-email")]
        public IActionResult OtpEmail([FromBody] User user)
        {
            db.startConnection();
            db.openConnection();
            JsonFactory jsonFactory = new JsonFactory();

            try
            {
                string guid = db.sendOTPEmail(user);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseOtpEmail(user, guid));

            }
            catch (Exception ex)
            {
                return Ok(StatusCode(401, jsonFactory.generateBadJson("There was a problem with the response body")));
            } 
            
           
        }

        //[HttpPost("/auth/verify-password")]
        //public IActionResult Salt(string password, string hash)
        //{

        //    bool isCorrect = passwordHasher.VerifyPassword(password, hash);
        //    return Ok(isCorrect);
        //}

        [HttpPost("/auth/send-otp-to-phone")]
        public async Task<IActionResult> OtpPhone([FromBody]User user)
        {
            JsonFactory jsonFactory = new JsonFactory();
            JsonResponseOtp responseOtp = new JsonResponseOtp();
            JsonResponseFromKerry resp = new JsonResponseFromKerry();

            try
            {
                decimal phone = Convert.ToDecimal(user.PhoneNo);
                if(user.PhoneNo.Length == 10)
                {
                    resp = await otpProvider.SendOtpToPhoneHelper(user.PhoneNo);
                    responseOtp = jsonFactory.generateResponseOtpPhone(resp);
                    return Ok(responseOtp);
                }
                return Ok(StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body")));
            }
            catch (Exception e)
            {
                return Ok(StatusCode(401,jsonFactory.generateBadJson("There was a problem with the request body")));
            }
        }

        //[HttpPost("/auth/verify-phone-otp")]
        //public async Task<IActionResult> VerifyOtp([FromBody] OtpVerificationRequestBody otpVerificationRequestBody)
        //{
        //    JsonResponse response = new JsonResponse();
        //    JsonResponseOtpVerification responseOtp = new JsonResponseOtpVerification();
        //    OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
        //    db.startConnection();
        //    db.openConnection();
        //    try
        //    {
        //        resp = await otpProvider.VerifyOTP(otpVerificationRequestBody);
        //        responseOtp = new JsonResponseOtpVerification();
        //        responseOtp = response.successOtp(resp);
        //        db.closeConnection();
        //        return Ok(responseOtp);
        //    }
        //    catch (Exception e)
        //    {
        //        db.closeConnection();
        //        return Ok(response.badAuthOtp());
        //    }
        //}








        //check if user exists
        //bool ifExists = db.executeProcedureCheckIfUserExists(user);
        //if(ifExists)
        //{
        //    return Ok(response.success(displayEn: "Account already exists", displayTh: "บัญชีมีอยู่แล้ว"));
        //}

        //string? otp;
        //string? guid;
        //try
        //{
        //    otp = otpProvider.sendOTP(user.PhoneNo);
        //    guid = Guid.NewGuid().ToString();
        //    db.insertIntoOtpTable(guid, otp, user.PhoneNo);
        //    db.closeConnection();
        //    responseOtp = response.successOtp(otp, guid);
        //    return Ok(responseOtp);
        //}
        //catch(Exception e)
        //{
        //    return Ok(StatusCode(401, response.badAuthOtp()));
        //}    
    

        [HttpPost("/auth/check-user-exist")]
        public IActionResult CheckIfUserExists([FromBody] User user)
        {
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifUserExists = procedure.executeProcedureCheckIfUserExists(user);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseUserExist(ifUserExists));             
            }
            catch(Exception e)
            {
                return Ok(StatusCode(401,jsonFactory.generateBadJson("There is an error with the response body")));
            }
           
        }


    }
}
