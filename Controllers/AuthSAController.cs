﻿using AuthSA.Model;
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
        public async Task<IActionResult> VerifyOtp([FromBody] OtpVerificationRequestBody otpVerificationRequestBody)
        {
            JsonResponseOtpVerification responseOtp = new JsonResponseOtpVerification();
            OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();
            try
            {
                resp = await otpProvider.VerifyOTP(otpVerificationRequestBody);
                responseOtp = new JsonResponseOtpVerification();
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


        [HttpPost("/auth/check-user-exist")]
        public IActionResult CheckIfUserExists([FromBody] checkUserExistsRequestBody userDetails)
        {
            JsonFactory jsonFactory = new JsonFactory();
            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifUserExists = procedure.executeProcedureCheckIfUserExists(userDetails);
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
