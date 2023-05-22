using AuthSA.Model;
using AuthSA.Service.Database;
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
        JsonFactory jsonFactory = new JsonFactory();

        public bool checkAuthAPIKey()
        {
            string apiKey = Request.Headers["API-Key"];
            if(apiKey == "c6db5f66-8d1a-4498-833d-d2bc2349cd06")
            {
                return true;
            }

            return false;
        }

        [HttpPost("/auth/sign-up")]
        public IActionResult SignUp([FromBody] User user)
        {
            if(checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
            
            db.startConnection();
            db.openConnection();
            if(procedure.executeProcedureCheckIfUserExists(PhoneNo: user.PhoneNo) || procedure.executeProcedureCheckIfUserExists(Email: user.Email))
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }

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
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
        }



        [HttpPost("/auth/send-otp-to-email")]
        public IActionResult OtpEmail([FromBody] sendEmailOtpRequestBody emailRequest)
        {

            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
            db.startConnection();
            db.openConnection();
          
            try
            {
                string guid = otpProvider.sendOTPEmail(emailRequest.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseOtpEmail(emailRequest, guid));

            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the response body"));
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
            JsonResponseOtp responseOtp = new JsonResponseOtp();
            JsonResponseFromKerry resp = new JsonResponseFromKerry();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
            try
            {
                decimal phone = Convert.ToDecimal(phoneNo.PhoneNo);
                if(phoneNo.PhoneNo.Length == 10)
                {
                    resp = await otpProvider.SendOtpToPhoneHelper(phoneNo.PhoneNo);
                    responseOtp = jsonFactory.generateResponseOtpPhone(resp);
                    return Ok(responseOtp);
                }
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the response body"));
            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the response body"));
            }
        }

        [HttpPost("/auth/verify-phone-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpPhoneVerificationRequestBody otpVerificationRequestBody)
        {
            JsonResponseOtpPhoneVerification responseOtp = new JsonResponseOtpPhoneVerification();
            OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
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
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the response body"));
            }
        }

        [HttpPost("/auth/verify-email-otp")]
        public async Task<IActionResult> VerifyEmailOtp([FromBody] OtpEmailVerificationRequestBody requestBody)
        {
            JsonResponseOtpEmailVerification response = new JsonResponseOtpEmailVerification();

            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }
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
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
            }
            
        }


        [HttpPost("/auth/check-user-exist")]
        public IActionResult CheckIfUserExists([FromBody] checkUserExistsRequestBody userDetails)
        {

            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }   
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
           
        }


    }
}
