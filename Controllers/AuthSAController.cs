using AuthSA.Model;
using AuthSA.Service;
using AuthSA.Service.Database;
using AuthSA.Util;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace AuthSA.Controllers
{
    public class AuthSAController : Controller
    {
        TokenService tokenService = new TokenService("abcdefghijklmnopqrstuvwxyz");
        PasswordHasher passwordHasher = new PasswordHasher();
        OTPProvider otpProvider = new OTPProvider();
        Database db = new Database();
        Procedure procedure = new Procedure();
        JsonFactory jsonFactory = new JsonFactory();


        public bool checkAuthAPIKey()
        {
            string apiKey = Request.Headers["API-Key"];
            if (apiKey == "c6db5f66-8d1a-4498-833d-d2bc2349cd06")
            {
                return true;
            }

            return false;
        }

        [HttpPost("/auth/sign-up")]
        public IActionResult SignUp([FromBody] User user)
        {
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            db.startConnection();
            db.openConnection();
            if (procedure.executeProcedureCheckIfUserExists(PhoneNo: user.PhoneNo) || procedure.executeProcedureCheckIfUserExists(Email: user.Email))
            {
                return StatusCode(401, jsonFactory.generateBadJson("User already exists"));
            }

            try
            {
                user.UserId = Guid.NewGuid().ToString();
                string hashed = passwordHasher.HashPassword(user);
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
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
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


        [HttpPost("/auth/send-otp-to-phone")]
        public async Task<IActionResult> OtpPhone([FromBody] sendPhoneOtpRequestBody phoneNo)
        {
            JsonResponseOtp responseOtp = new JsonResponseOtp();
            JsonResponseFromKerry resp = new JsonResponseFromKerry();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }
            try
            {
                decimal phone = Convert.ToDecimal(phoneNo.PhoneNo);
                if (phoneNo.PhoneNo.Length == 10)
                {
                    resp = await otpProvider.SendOtpToPhoneHelper(phoneNo.PhoneNo);
                    responseOtp = jsonFactory.generateResponseOtpPhone(resp);
                    return Ok(responseOtp);
                }
                return StatusCode(401, jsonFactory.generateBadJson("Format is wrong"));
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
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
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
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
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
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
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
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }

        }


        [HttpPost("/auth/reset-password")]
        public IActionResult ResetPassword([FromBody] ResetPasswordRequestBody requestBody)
        {
            try
            {
                if (checkAuthAPIKey() == false || Request.Headers["Authorization"].IsNullOrEmpty())
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                db.startConnection();
                db.openConnection();

                string accessToken;

                //Get access token
                accessToken = Request.Headers["Authorization"];

                if (accessToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    accessToken = accessToken.Substring("Bearer ".Length);
                }
                else
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                //check if token is expired
                bool ifExpired = procedure.executeProcedureCheckExpiryAccessToken(accessToken);
                if (ifExpired)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Token has expired"));
                }

                //take access token to get UserId
                string? userId = procedure.executeProcedureGetUserIdByAccessToken(accessToken);

                // Call the stored procedure to get user phone and email
                string? userDetailsJson = procedure.executeProcedureGetUserPhoneEmail(userId);

                // Deserialize the JSON response into an array of UserEmailPhone objects
                UserEmailPhone[] userEmailPhones = JsonConvert.DeserializeObject<UserEmailPhone[]>(userDetailsJson);

                // Extract the first UserEmailPhone object from the array
                UserEmailPhone userPhoneEmail = userEmailPhones.FirstOrDefault();

                // You can now access the email and phone number as follows:
                string userEmail = userPhoneEmail?.Email;
                string userPhone = userPhoneEmail?.Phone_No;

                //check if requestbody email or phoneNo matches userDetails email or phoneNo
                if (requestBody.Email != null)
                {
                    if (requestBody.Email != userEmail)
                    {
                        db.closeConnection();
                        return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                    }
                }
                else if (requestBody.PhoneNo != null)
                {
                    if (requestBody.PhoneNo != userPhone)
                    {
                        db.closeConnection();
                        return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(401, jsonFactory.generateBadJson(ex.ToString()));
            }

            //update password
            try
            {


                string hashed = passwordHasher.HashPassword(new User() { Email = requestBody.Email, PhoneNo = requestBody.PhoneNo, Password = requestBody.Password });
                requestBody.Password = hashed;
                bool passwordIsOld = procedure.executeProcedureCheckPasswordisOld(requestBody);
                if (passwordIsOld)
                {

                    return StatusCode(401, jsonFactory.generateResponseResetPassword("This password is either old or current"));
                }
                procedure.executeProcedureResetPassword(hashed, requestBody.PhoneNo, requestBody.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseResetPassword());
            }
            catch (Exception)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }

        [HttpPost("/auth/login")]
        public IActionResult Login([FromBody] ResetPasswordRequestBody requestBody)
        {
            Token token = new Token();
            db.startConnection();
            db.openConnection();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifExists = procedure.executeProcedureCheckIfUserExists(requestBody.PhoneNo, requestBody.Email);
                if (!ifExists)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The user does not exist", "401"));
                }

                bool isCorrect = passwordHasher.VerifyPassword(requestBody.Password, requestBody.Email, requestBody.PhoneNo);
                if (isCorrect)
                {
                    //Todo: Fix the generation of tokens. After generate, store the tokens, their expiry date, userId, and insert 1 in isLoggedIn
                    string? userId = procedure.executeProcedureGetUserId(requestBody.Email, requestBody.PhoneNo);
                    token.AccessToken = tokenService.GenerateAccessToken(userId);
                    token.RefreshToken = tokenService.GenerateRefreshToken();
                    procedure.executeProcedureInsertIntoUserStatus(userId, token.AccessToken, token.RefreshToken);

                    return Ok(token);
                    //gen tokens
                }

                db.closeConnection();
                return StatusCode(401, jsonFactory.generateResponseResetPassword("Invalid", "401"));
            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }


        [HttpPost("/auth/generate-access-token")]
        public IActionResult GetNewAccessToken([FromBody] GenerateAccessTokenRequestBody requestBody)
        {
            Token token = new Token();
            db.startConnection();
            db.openConnection();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }



            try
            {
                if (procedure.executeProcedureCheckExpiryRefreshToken(requestBody.RefreshToken))
                {
                    procedure.executeProcedureDeleteSession(requestBody.RefreshToken);
                    return StatusCode(401, jsonFactory.generateBadJson("Refresh Token has expired"));
                }
                if (!procedure.executeProcedureCheckIfTokensExist(requestBody.RefreshToken, requestBody.AccessToken))
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                string? userId = procedure.executeProcedureGetUserIdByRefreshToken(requestBody.RefreshToken);
                if (userId.IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                token.RefreshToken = requestBody.RefreshToken;
                token.AccessToken = tokenService.GenerateAccessToken(userId);

                //update in db then return the tokens
                procedure.executeProcedureUpdateAccessToken(requestBody.RefreshToken, token.AccessToken);
                db.closeConnection();
                AccessToken accessToken = new AccessToken() { accessToken = token.AccessToken };
                return Ok(accessToken);
            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }

        [HttpGet("/auth/check-access-token-expiry")]
        public IActionResult CheckAccessTokenExpiry()
        {
            db.startConnection();
            db.openConnection();
            string? bearer = "";
            try
            {
                bearer = Request.Headers["Authorization"];
                if (bearer.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    bearer = bearer.Substring("Bearer ".Length);
                }
                else
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                if (!procedure.executeProcedureCheckIfAccessTokenExist(bearer) || checkAuthAPIKey() == false || bearer.IsNullOrEmpty())
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }


            try
            {
                bool isExpired = procedure.executeProcedureCheckExpiryAccessToken(bearer);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseCheckExpiry(isExpired));
            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }


        [HttpGet("/auth/logout")]
        public IActionResult Logout()
        {
            db.startConnection();
            db.openConnection();
            string accessToken = "";
            string refreshToken = "";
            try
            {
                accessToken = Request.Headers["X-Access-Token"];
                refreshToken = Request.Headers["X-Refresh-Token"];

                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                if (!procedure.executeProcedureCheckIfTokensExist(refreshToken, accessToken) || checkAuthAPIKey() == false || accessToken.IsNullOrEmpty() || refreshToken.IsNullOrEmpty())
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }


            try
            {
                procedure.executeProcedureDeleteSession(refreshToken, accessToken);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseLogout());
            }
            catch (Exception)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }


        [HttpPost("/auth/forget-password-phone")]
        public async Task<IActionResult> ForgetPasswordPhone([FromBody] ForgetPasswordPhoneRequestBody requestBody)
        {

            OtpPhoneVerificationRequestBody phoneVerificationRequestBody = new OtpPhoneVerificationRequestBody();
            phoneVerificationRequestBody.Otp = requestBody.phoneVerificationRequestBody.Otp;
            phoneVerificationRequestBody.Reference = requestBody.phoneVerificationRequestBody.Reference;
            phoneVerificationRequestBody.Token = requestBody.phoneVerificationRequestBody.Token;
            db.startConnection();
            db.openConnection();
            if (!procedure.executeProcedureCheckIfUserExists(requestBody.PhoneNo, requestBody.Email))
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }
            try
            {
                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                //call otp verificaiton api
                try
                {
                    OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
                    resp = await otpProvider.VerifyOTP(phoneVerificationRequestBody);
                    if (resp.Recipient != requestBody.PhoneNo)
                    {
                        return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                    }
                }
                catch(Exception)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Otp/Ref/Token incorrect"));
                }              
            }
            catch (Exception ex)
            {
                return StatusCode(401, jsonFactory.generateBadJson(ex.ToString()));
            }

            //update password
            try
            {
                string hashed = passwordHasher.HashPassword(new User() { Email = requestBody.Email, PhoneNo = requestBody.PhoneNo, Password = requestBody.Password });
                requestBody.Password = hashed;
                ResetPasswordRequestBody resetPasswordRequestBody = new ResetPasswordRequestBody();
                resetPasswordRequestBody.Email = requestBody.Email;
                resetPasswordRequestBody.Password = requestBody.Password;
                resetPasswordRequestBody.PhoneNo = requestBody.PhoneNo;
                bool passwordIsOld = procedure.executeProcedureCheckPasswordisOld(resetPasswordRequestBody);
                if (passwordIsOld)
                {

                    return StatusCode(401, jsonFactory.generateResponseResetPassword("This password is either old or current","401"));
                }
                procedure.executeProcedureResetPassword(hashed, requestBody.PhoneNo, requestBody.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseResetPassword());
            }
            catch (Exception)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body"));
            }
        }

        [HttpPost("/auth/forget-password-email")]
        public Task<IActionResult> ForgetPasswordEmail([FromBody] ForgetPasswordEmailRequestBody requestBody)
        {
            db.startConnection();
            db.openConnection();

            OtpEmailVerificationRequestBody emailVerificationRequestBody = new OtpEmailVerificationRequestBody();
            emailVerificationRequestBody.Otp = requestBody.emailVerificationRequestBody.Otp;
            emailVerificationRequestBody.Email = requestBody.emailVerificationRequestBody.Email;
            emailVerificationRequestBody.Token = requestBody.emailVerificationRequestBody.Token;
            JsonResponseOtpEmailVerification response = new JsonResponseOtpEmailVerification();   
            if (!procedure.executeProcedureCheckIfUserExists(requestBody.PhoneNo, requestBody.Email))
            {
                db.closeConnection();
                return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("Unauthorized")));
            }
            try
            {
                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("Unauthorized")));
                }

                //call otp verificaiton api for email
                bool istrue = procedure.executeProcedureVerifyEmailOtp(emailVerificationRequestBody.Token, emailVerificationRequestBody.Otp, emailVerificationRequestBody.Email);
                if (!istrue)
                {
                    db.closeConnection();
                    return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("Otp/Token incorrect")));
                }
            }
            catch (Exception ex)
            {
                return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson(ex.ToString())));
            }

            //update password
            try
            {
                string hashed = passwordHasher.HashPassword(new User() { Email = requestBody.Email, PhoneNo = requestBody.PhoneNo, Password = requestBody.Password });
                requestBody.Password = hashed;
                ResetPasswordRequestBody resetPasswordRequestBody = new ResetPasswordRequestBody();
                resetPasswordRequestBody.Email = requestBody.Email;
                resetPasswordRequestBody.Password = requestBody.Password;
                resetPasswordRequestBody.PhoneNo = requestBody.PhoneNo;
                bool passwordIsOld = procedure.executeProcedureCheckPasswordisOld(resetPasswordRequestBody);
                if (passwordIsOld)
                {

                    return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateResponseResetPassword("This password is either old or current", "401")));
                }
                procedure.executeProcedureResetPassword(hashed, requestBody.PhoneNo, requestBody.Email);
                db.closeConnection();
                return Task.FromResult<IActionResult>(Ok(jsonFactory.generateResponseResetPassword()));
            }
            catch (Exception)
            {
                db.closeConnection();
                return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("There is an error with the response body")));
            }
        }
    }
}
