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

        [HttpPost("/auth/sign-up")]
        public IActionResult SignUp([FromBody] User user)
        {
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();
            if (!procedure.executeProcedureCheckIfUserExists(Email: user.Email) || !procedure.executeProcedureCheckIfUserExists(PhoneNo: user.PhoneNo))
            {
                try
                {
                    string hashed = passwordHasher.HashPassword(user);
                    user.Password = hashed;
                    string? salt = passwordHasher.GetSalt(user);
                    procedure.insertIntoPasswordTable(user, salt);
                    procedure.insertIntoUserTable(user);
                    db.closeConnection();
                    return Ok(jsonFactory.generateResponseSignUp());
                }
                catch (Exception)
                {
                    return Ok(jsonFactory.generateBadJson("There was an error"));
                }
            }
            else
            {
                return Ok(jsonFactory.generateBadJson("User already exists"));
            }
                
            


        }



        [HttpPost("/auth/send-otp-to-email")]
        public IActionResult OtpEmail([FromBody] sendEmailOtpRequestBody emailRequest)
        {
            db.startConnection();
            db.openConnection();
            JsonFactory jsonFactory = new JsonFactory();

            try
            {
                string guid = otpProvider.sendOTPEmail(emailRequest.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseOtpEmail(emailRequest, guid));

            }
            catch (Exception)
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
        public async Task<IActionResult> OtpPhone([FromBody] sendPhoneOtpRequestBody phoneNo)
        {
            JsonFactory jsonFactory = new JsonFactory();
            JsonResponseOtp responseOtp = new JsonResponseOtp();
            JsonResponseFromKerry resp = new JsonResponseFromKerry();

            try
            {
                decimal phone = Convert.ToDecimal(phoneNo.PhoneNo);
                if(phoneNo.PhoneNo.Length == 10)
                {
                    resp = await otpProvider.SendOtpToPhoneHelper(phoneNo.PhoneNo);
                    responseOtp = jsonFactory.generateResponseOtpPhone(resp);
                    return Ok(responseOtp);
                }
                return Ok(StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body")));
            }
            catch (Exception)
            {
                return Ok(StatusCode(401,jsonFactory.generateBadJson("There was a problem with the request body")));
            }
        }

        [HttpPost("/auth/verify-phone-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpPhoneVerificationRequestBody otpVerificationRequestBody)
        {
            JsonResponseOtpPhoneVerification responseOtp = new JsonResponseOtpPhoneVerification();
            OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();
            try
            {
                resp = await otpProvider.VerifyOTP(otpVerificationRequestBody);
                responseOtp = new JsonResponseOtpPhoneVerification();
                responseOtp = jsonFactory.generateSuccessfulOtpPhoneVerificicationResponse(resp);
                db.closeConnection();
                return Ok(responseOtp);
            }
            catch (Exception)
            {
                db.closeConnection();
                return Ok(StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body")));
            }
        }

        [HttpPost("/auth/verify-email-otp")]
        public async Task<IActionResult> VerifyEmailOtp([FromBody] OtpEmailVerificationRequestBody requestBody)
        {
            JsonResponseOtpEmailVerification response = new JsonResponseOtpEmailVerification();
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();
            try
            {
                bool istrue = procedure.executeProcedureVerifyEmailOtp(requestBody.Token, requestBody.Otp, requestBody.Email);
                response = jsonFactory.generateSuccessfulOtpEmailVerificicationResponse(requestBody, istrue);
                db.closeConnection();
                return Ok(response);
            }
            catch (Exception)
            {
                db.closeConnection();
                return Ok(StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body")));
            }
            
        }


        [HttpPost("/auth/check-user-exist")]
        public IActionResult CheckIfUserExists([FromBody] checkUserExistsRequestBody userDetails)
        {
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifUserExists = procedure.executeProcedureCheckIfUserExists(userDetails.PhoneNo, userDetails.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseUserExist(ifUserExists));             
            }
            catch(Exception)
            {
                return Ok(StatusCode(401,jsonFactory.generateBadJson("There is an error with the response body")));
            }
           
        }


    }
}
