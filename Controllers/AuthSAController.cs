using AuthSA.Model;
using AuthSA.Service;
using AuthSA.Service.Database;
using AuthSA.Util;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

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
        public async Task<IActionResult> SignUp([FromBody] SignupRequestBody requestBody)
        {
            User user = requestBody.user;
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

            //verify phone otp
            OtpPhoneVerificationRequestBody phoneVerificationRequestBody = new OtpPhoneVerificationRequestBody();
            phoneVerificationRequestBody.Otp = requestBody.phoneVerificationRequestBody.Otp;
            phoneVerificationRequestBody.Reference = requestBody.phoneVerificationRequestBody.Reference;
            phoneVerificationRequestBody.Token = requestBody.phoneVerificationRequestBody.Token;
            //call otp verificaiton api for phone
            try
            {
                OtpVerificationJsonResponseKerry resp = new OtpVerificationJsonResponseKerry();
                resp = await otpProvider.VerifyOTP(phoneVerificationRequestBody);
                if (resp.Recipient != user.PhoneNo)
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
            }
            catch (Exception)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("Otp/Ref/Token for phone incorrect"));
            }

            //verify email otp
            OtpEmailVerificationRequestBody emailVerificationRequestBody = new OtpEmailVerificationRequestBody();
            emailVerificationRequestBody.Otp = requestBody.emailVerificationRequestBody.Otp;
            emailVerificationRequestBody.Token = requestBody.emailVerificationRequestBody.Token;
            JsonResponseOtpEmailVerification response = new JsonResponseOtpEmailVerification();
            //call otp verificaiton api for email
            string emailOtp = procedure.executeProcedureVerifyEmailOtp(emailVerificationRequestBody.Token, emailVerificationRequestBody.Otp);
            if (emailOtp.IsNullOrEmpty() || emailOtp!=user.Email)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("Otp/Token for email incorrect or expired"));
            }

            //if above checks pass, proceed to sign up
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
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
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
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
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
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
            }
        }

        [HttpPost("/auth/verify-email-otp")]
        public IActionResult VerifyEmailOtp([FromBody] OtpEmailVerificationRequestBody requestBody)
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
                string otpEmail = procedure.executeProcedureVerifyEmailOtp(requestBody.Token, requestBody.Otp);
                if (otpEmail.IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Otp is wrong or expired"));
                }
                response = jsonFactory.generateSuccessfulOtpEmailVerificicationResponse(requestBody, true, otpEmail);
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }

        }


        [HttpPost("/auth/reset-password")]
        public IActionResult ResetPassword([FromHeader(Name = "Authorization")][Required] string Access, [FromBody] ResetPasswordRequestBody requestBody)
        {
            try
            {
                bool api = checkAuthAPIKey();
                bool header = Request.Headers["Authorization"].IsNullOrEmpty();
                string accessToken;

                //Get access token
                accessToken = Request.Headers["Authorization"];
                if (checkAuthAPIKey() == false || Request.Headers["Authorization"].IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                db.startConnection();
                db.openConnection();

                //string accessToken;

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
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was an error"));
            }

            //update password
            try
            {
                //check if old password is entered is the correct password
                bool isCorrect = passwordHasher.VerifyPassword(password: requestBody.CurrentPassword, phoneNo: requestBody.PhoneNo, email: requestBody.Email);
                if (!isCorrect)
                {
                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The current password is wrong"));
                }

                //check if new password is old
                string hashedNewPassword = passwordHasher.HashPassword(new User() { Email = requestBody.Email, PhoneNo = requestBody.PhoneNo, Password = requestBody.NewPassword });
                requestBody.NewPassword = hashedNewPassword;
                bool passwordIsOld = procedure.executeProcedureCheckPasswordisOld(requestBody);
                if (passwordIsOld)
                {

                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The new password is either old or current"));
                }

                procedure.executeProcedureResetPassword(hashedNewPassword, requestBody.PhoneNo, requestBody.Email);
                db.closeConnection();
                return Ok(jsonFactory.generateResponseResetPassword());
            }
            catch (Exception)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }

        [HttpPost("/auth/login-by-phone")]
        public async Task<IActionResult> LoginByPhoneAsync([FromBody] LoginByPhone requestBody)
        {
            Token token = new Token();

            OtpPhoneVerificationRequestBody phoneVerificationRequestBody = new OtpPhoneVerificationRequestBody();
            phoneVerificationRequestBody.Otp = requestBody.phoneVerificationRequestBody.Otp;
            phoneVerificationRequestBody.Reference = requestBody.phoneVerificationRequestBody.Reference;
            phoneVerificationRequestBody.Token = requestBody.phoneVerificationRequestBody.Token;
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifExists = procedure.executeProcedureCheckIfUserExists(requestBody.PhoneNo);
                if (!ifExists)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The user does not exist", "401"));
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
                catch (Exception)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Otp/Ref/Token incorrect"));
                }

                //login
                bool isCorrect = passwordHasher.VerifyPassword(requestBody.Password, phoneNo: requestBody.PhoneNo);
                if (isCorrect)
                {
                    string? userId = procedure.executeProcedureGetUserId(phoneNo: requestBody.PhoneNo);
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }

        [HttpPost("/auth/login-by-email")]
        public async Task<IActionResult> LoginByEmail([FromBody] LoginByEmail requestBody)
        {
            Token token = new Token();

            OtpEmailVerificationRequestBody emailVerificationRequestBody = new OtpEmailVerificationRequestBody();
            emailVerificationRequestBody.Otp = requestBody.emailVerificationRequestBody.Otp;
            emailVerificationRequestBody.Token = requestBody.emailVerificationRequestBody.Token;
            JsonResponseOtpEmailVerification jsonResponseOtpEmailVerification = new JsonResponseOtpEmailVerification();
            if (checkAuthAPIKey() == false)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            db.startConnection();
            db.openConnection();

            try
            {
                //check if user exists in db
                bool ifExists = procedure.executeProcedureCheckIfUserExists(Email: requestBody.Email);
                if (!ifExists)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The user does not exist", "401"));
                }

                //call otp verificaiton api
                try
                {
                    //call otp verificaiton api for email
                    string email = procedure.executeProcedureVerifyEmailOtp(emailVerificationRequestBody.Token, emailVerificationRequestBody.Otp);
                    if (email.IsNullOrEmpty() || email != requestBody.Email)
                    {
                        db.closeConnection();
                        return await Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("Otp/Token incorrect or expired")));
                    }
                }
                catch (Exception)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Otp/Ref/Token incorrect"));
                }

                //login
                bool isCorrect = passwordHasher.VerifyPassword(requestBody.Password, email: requestBody.Email);
                if (isCorrect)
                {
                    string? userId = procedure.executeProcedureGetUserId(email: requestBody.Email);
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }

        [HttpGet("/auth/check-access-token-expiry")]
        public IActionResult CheckAccessTokenExpiry([FromHeader(Name = "Authorization")][Required] string Access)
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }


        [HttpGet("/auth/logout")]
        public IActionResult Logout([FromHeader(Name = "X-Access-Token")][Required] string Access, [FromHeader(Name = "X-Refresh-Token")][Required] string Refresh)
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
                return StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }

        [HttpPost("/auth/forget-password-phone")]
        public async Task<IActionResult> ForgetPasswordPhone([FromBody] ForgetPasswordPhoneRequestBody requestBody)
        {
            try
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
                    catch (Exception)
                    {
                        db.closeConnection();
                        return StatusCode(401, jsonFactory.generateBadJson("Otp/Ref/Token incorrect"));
                    }
                }
                catch (Exception ex)
                {
                    return StatusCode(401, jsonFactory.generateBadJson(ex.ToString()));
                }
            }
            catch (Exception)
            {
              
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }


            //update password
            try
            {
                string hashed = passwordHasher.HashPassword(new User() { Email = requestBody.Email, PhoneNo = requestBody.PhoneNo, Password = requestBody.Password });
                requestBody.Password = hashed;
                ResetPasswordRequestBody resetPasswordRequestBody = new ResetPasswordRequestBody();
                resetPasswordRequestBody.Email = requestBody.Email;
                resetPasswordRequestBody.NewPassword = requestBody.Password;
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
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }
        }

        [HttpPost("/auth/forget-password-email")]
        public Task<IActionResult> ForgetPasswordEmail([FromBody] ForgetPasswordEmailRequestBody requestBody)
        {
            db.startConnection();
            db.openConnection();

            OtpEmailVerificationRequestBody emailVerificationRequestBody = new OtpEmailVerificationRequestBody();
            emailVerificationRequestBody.Otp = requestBody.emailVerificationRequestBody.Otp;
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
                string email = procedure.executeProcedureVerifyEmailOtp(emailVerificationRequestBody.Token, emailVerificationRequestBody.Otp);
                if (email.IsNullOrEmpty() || email != requestBody.Email)
                {
                    db.closeConnection();
                    return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("Otp/Token incorrect or expired")));
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
                resetPasswordRequestBody.NewPassword = requestBody.Password;
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
                return Task.FromResult<IActionResult>(StatusCode(401, jsonFactory.generateBadJson("There is an error with the request body")));
            }
        }

        [HttpPost("/auth/qr-login")]
        public IActionResult QrLogin([FromHeader(Name = "Authorization")][Required] string Access, [FromBody]QrLoginRequestBody requestBody)
        {
            try
            {
                //accept access token in header and qr token in body
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
                if (userId.IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }


                //insert qr token and user id into token table
                procedure.insertIntoTokenTable(userId, requestBody.Token);
                //use another api for web which takes in the qr token and checks whether the token exists in token table. if yes then login for the web, meaning generate access and refresh token. store them in db with the user id thats in the token table
                return Ok(jsonFactory.generateSuccessfulQrLoginResponse());
            }
            catch (Exception ex)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }
            
        }

        [HttpPost("/auth/check-if-token-in-use")]
        public IActionResult LoginQrWeb([FromBody] QrLoginRequestBody requestBody)
        {
            try
            {
                db.startConnection();
                db.openConnection();

                //check api key
                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                //accept token

                //check if token is in token db
                //if yes then get user id from the token db
                string? userId = procedure.executeProcedureGetUserIdByTokenId(requestBody.Token);
                if (userId.IsNullOrEmpty())
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }
                //generate access and refresh token and insert in user status table
                Token token = new Model.Token();
                token.AccessToken = tokenService.GenerateAccessToken(userId);
                token.RefreshToken = tokenService.GenerateRefreshToken();
                procedure.executeProcedureInsertIntoUserStatus(userId, token.AccessToken, token.RefreshToken);
                //return access and refresh token
                return Ok(token);
            }
            catch (Exception)
            {
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }
    
        }

        [HttpPost("/auth/get-email")]
        public IActionResult GetEmailByPhoneNo([FromBody] getEmailFromPhoneRequestBody requestBody)
        {
            //check api key
            if (checkAuthAPIKey() == false)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            Util.Util util = new Util.Util();
            string? email;
            try
            {
                if (!util.IsValidPhoneNumber(requestBody.phoneNo))
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Wrong Format"));
                }
                email = procedure.ExecuteProcedureGetEmailByPhoneNumber(requestBody.phoneNo);
                if (email.IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Phone number or Email does not exist"));
                }
                return Ok(jsonFactory.generateSuccessfulGetEmailResponse(email));
            }
            catch(Exception e)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
            }
            
        }

        [HttpPost("/auth/get-phone-no")]
        public IActionResult GetPhoneNoByEmail([FromBody] getPhoneFromPhoneRequestBody requestBody)
        {
            //check api key
            if (checkAuthAPIKey() == false)
            {
                db.closeConnection();
                return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
            }

            Util.Util util = new Util.Util();
            string? phoneNo;
            try
            {
                if (!util.IsValidEmail(requestBody.email))
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Wrong Format"));
                }
                phoneNo = procedure.ExecuteProcedureGetPhoneNumberByEmail(requestBody.email);
                if (phoneNo.IsNullOrEmpty())
                {
                    return StatusCode(401, jsonFactory.generateBadJson("Phone number or Email does not exist"));
                }
                return Ok(jsonFactory.generateSuccessfulGetPhoneNoResponse(phoneNo));
            }
            catch (Exception e)
            {
                return StatusCode(401, jsonFactory.generateBadJson("There was a problem with the request body"));
            }   

        }

        [HttpPost("/auth/check-credentials")]
        public IActionResult CheckCredentials([FromBody] checkCredentialsRequestBody requestBody)
        {
            try
            {
                db.startConnection();
                db.openConnection();
                //check api key
                if (checkAuthAPIKey() == false)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateBadJson("Unauthorized"));
                }

                //check if user exists in db
                bool ifExists = procedure.executeProcedureCheckIfUserExists(Email: requestBody.Email, PhoneNo: requestBody.PhoneNo);
                if (!ifExists)
                {
                    db.closeConnection();
                    return StatusCode(401, jsonFactory.generateResponseResetPassword("The user does not exist", "401"));
                }

                //login
                bool isCorrect = passwordHasher.VerifyPassword(requestBody.Password, email: requestBody.Email, phoneNo: requestBody.PhoneNo);
                if (isCorrect)
                {
                    db.closeConnection();
                    return Ok(jsonFactory.generateSuccessfulCheckCredentials(isCorrect));
                }
                else
                {
                    db.closeConnection();
                    return StatusCode(401,jsonFactory.generateSuccessfulCheckCredentials(isCorrect));
                }
            }
            catch (Exception)
            {
                return StatusCode(401,jsonFactory.generateBadJson("There is an error with the request body"));
            }
        }

        [HttpPost("/god-mode/delete-user")]
        public IActionResult DeleteUser([FromBody] sendEmailOtpRequestBody requestBody)
        {
            try
            {
                db.startConnection();
                db.openConnection();

                procedure.executeProcedureDeleteUserByEmail(requestBody.Email);
                bool ifExists = procedure.executeProcedureCheckIfUserExists(Email: requestBody.Email);
                db.closeConnection();
                if (!ifExists)
                {
                    return Ok("User doesnt exist");
                }
                return Ok("User deleted");
            }
            catch(Exception)
            {
                throw new Exception("There was a problem");
            }
        }
    }
}
