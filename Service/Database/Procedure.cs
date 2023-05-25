using AuthSA.Model;
using AuthSA.Util;
using System.Data;
using System.Data.SqlClient;

namespace AuthSA.Service.Database
{
    public class Procedure
    {
        Util.Util util = new Util.Util();
        Database db = new Database();
        public void insertIntoPasswordTable(User user, string salt)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO Password(UserId, Email, Phone_No, CurrentPassword, Salt) values ('{user.UserId}', N'{user.Email.ToLower()}', N'{user.PhoneNo}',N'{user.Password}', N'{salt}')", db.Connection);
            getLabelDetails.ExecuteNonQuery();
            db.closeConnection();
        }

        public void executeProcedureInsertIntoUserStatus(string userId, string accessToken, string refreshToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.InsertUserStatus  @UserId, @Access_Token, @Refresh_Token", db.Connection);

            ifExists.Parameters.AddWithValue("@UserId", (object)userId);
            ifExists.Parameters.AddWithValue("@Access_Token", (object)accessToken);
            ifExists.Parameters.AddWithValue("@Refresh_Token", (object)refreshToken);
            ifExists.ExecuteNonQuery();
            db.closeConnection();

        }

        public void executeProcedureUpdateAccessToken(string refreshToken, string accessToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.UpdateAccessToken  @Refresh_Token, @Access_Token", db.Connection);
            ifExists.Parameters.AddWithValue("@Refresh_Token", (object)refreshToken);
            ifExists.Parameters.AddWithValue("@Access_Token", (object)accessToken);
            ifExists.ExecuteNonQuery();
            db.closeConnection() ;


        }
        public string? executeProcedureGetSalt(string email = null, string phoneNo = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(phoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetSalt  @Email, @PhoneNo", db.Connection);

            ifExists.Parameters.AddWithValue("@Email", (object)email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@PhoneNo", (object)phoneNo ?? DBNull.Value);

            if (email != null && !util.IsValidEmail(email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (phoneNo != null && !util.IsValidPhoneNumber(phoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }


            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string salt = "";
            if (readerLabelDetails.Read())
            {
                salt = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return salt;
        }


        public string? executeProcedureGetUserId(string email = null, string phoneNo = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(phoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetUserId  @Email, @PhoneNo", db.Connection);

            ifExists.Parameters.AddWithValue("@Email", (object)email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@PhoneNo", (object)phoneNo ?? DBNull.Value);

            if (email != null && !util.IsValidEmail(email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (phoneNo != null && !util.IsValidPhoneNumber(phoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }


            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string userId = "";
            if (readerLabelDetails.Read())
            {
                userId = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return userId;
        }

        public string? executeProcedureGetUserIdByRefreshToken(string refreshToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetUserIdByRefreshToken  @RefreshToken", db.Connection);

            ifExists.Parameters.AddWithValue("@RefreshToken ", (object)refreshToken);
            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string userId = "";
            if (readerLabelDetails.Read())
            {
                userId = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return userId;
        }

        public string? executeProcedureGetUserIdByAccessToken(string accessToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetUserIdByAccessToken  @AccessToken", db.Connection);

            ifExists.Parameters.AddWithValue("@AccessToken ", (object)accessToken);
            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string userId = "";
            if (readerLabelDetails.Read())
            {
                userId = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return userId;
        }
        public string? executeProcedureGetPassword(string email = null, string phoneNo = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(phoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetPassword  @Email, @PhoneNo", db.Connection);

            ifExists.Parameters.AddWithValue("@Email", (object)email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@PhoneNo", (object)phoneNo ?? DBNull.Value);

            if (email != null && !util.IsValidEmail(email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (phoneNo != null && !util.IsValidPhoneNumber(phoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }


            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string salt = "";
            if (readerLabelDetails.Read())
            {
                salt = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return salt;
        }

        public void insertIntoUserTable(User user)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO UserTable(UserId, First_Name, Last_Name, Email, Phone_No) values (N'{user.UserId}', N'{user.FirstName}', N'{user.LastName}',N'{user.Email.ToLower()}', N'{user.PhoneNo}')", db.Connection);
            getLabelDetails.ExecuteNonQuery();
            db.closeConnection();
        }

        public bool executeProcedureCheckIfUserExists(string PhoneNo = null, string Email = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(Email) && string.IsNullOrEmpty(PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfUserExists  @email, @phoneNum", db.Connection);

            ifExists.Parameters.AddWithValue("@email", (object)Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@phoneNum", (object)PhoneNo ?? DBNull.Value);

            if (Email != null && !util.IsValidEmail(Email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (PhoneNo != null && !util.IsValidPhoneNumber(PhoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }

            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public void executeProcedureDeleteSession(string refreshToken=null, string accessToken=null)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.DeleteUserSessionByTokens  @RefreshToken, @AccessToken", db.Connection);

            ifExists.Parameters.AddWithValue("@RefreshToken", (object)refreshToken ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@AccessToken", (object)accessToken ?? DBNull.Value);
            ifExists.ExecuteNonQuery();

            db.closeConnection();

        }

        public bool executeProcedureCheckExpiryRefreshToken(string refreshToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckRefreshTokenExpiry  @Refresh_Token", db.Connection);

            ifExists.Parameters.AddWithValue("@Refresh_Token", (object)refreshToken);
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public string? executeProcedureGetUserPhoneEmail(string userId)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand getUserPhoneEmail = new SqlCommand("EXEC dbo.getUserEmailPhoneById  @UserId", db.Connection);

            getUserPhoneEmail.Parameters.AddWithValue("@UserId", userId);
            SqlDataReader readerLabelDetails = getUserPhoneEmail.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            return result;
        }

        public bool executeProcedureCheckExpiryAccessToken(string accessToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckAccessTokenExpiry  @AccessToken", db.Connection);

            ifExists.Parameters.AddWithValue("@AccessToken", (object)accessToken);
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public bool executeProcedureCheckIfAccessTokenExist( string accessToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfAccessTokenExist  @AccessToken", db.Connection);

            ifExists.Parameters.AddWithValue("@AccessToken", (object)accessToken);
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public bool executeProcedureCheckIfTokensExist(string refreshToken, string accessToken)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckTokensExist  @RefreshToken, @AccessToken", db.Connection);

            ifExists.Parameters.AddWithValue("@RefreshToken", (object)refreshToken);
            ifExists.Parameters.AddWithValue("@AccessToken", (object)accessToken);
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public bool executeProcedureCheckIfSaltExists(string PhoneNo = null, string Email = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(Email) && string.IsNullOrEmpty(PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfSaltExists  @email, @phoneNum", db.Connection);

            ifExists.Parameters.AddWithValue("@email", (object)Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@phoneNum", (object)PhoneNo ?? DBNull.Value);

            if (Email != null && !util.IsValidEmail(Email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (PhoneNo != null && !util.IsValidPhoneNumber(PhoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }

            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }

        public bool executeProcedureCheckPasswordisOld(ResetPasswordRequestBody resetPasswordRequestBody)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(resetPasswordRequestBody.Email) && string.IsNullOrEmpty(resetPasswordRequestBody.PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckNewPasswordMatch  @Email, @PhoneNo, @NewPassword", db.Connection);



            ifExists.Parameters.AddWithValue("@Email", (object)resetPasswordRequestBody.Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@PhoneNo", (object)resetPasswordRequestBody.PhoneNo ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@NewPassword", (object)resetPasswordRequestBody.Password);

            if (resetPasswordRequestBody.Email != null && !util.IsValidEmail(resetPasswordRequestBody.Email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (resetPasswordRequestBody.PhoneNo != null && !util.IsValidPhoneNumber(resetPasswordRequestBody.PhoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }

            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            bool resultBool = Convert.ToBoolean(result.ToLower());
            return resultBool;
        }



        public void executeProcedureResetPassword(string password, string PhoneNo = null, string Email = null)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(Email) && string.IsNullOrEmpty(PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.UpdatePassword  @Email, @PhoneNo, @NewPassword", db.Connection);

            ifExists.Parameters.AddWithValue("@Email", (object)Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@PhoneNo", (object)PhoneNo ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@NewPassword", (object)password);

            if (Email != null && !util.IsValidEmail(Email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (PhoneNo != null && !util.IsValidPhoneNumber(PhoneNo))
            {
                db.closeConnection();
                throw new Exception();

            }
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
        }


        public string executeProcedureVerifyEmailOtp(string guid, string otp)
        {
            db.startConnection();
            db.openConnection();

            SqlCommand ifExists = new SqlCommand("dbo.CheckOtpEmail", db.Connection);
            ifExists.CommandType = CommandType.StoredProcedure;

            ifExists.Parameters.Add("@Guid", SqlDbType.VarChar).Value = guid;
            ifExists.Parameters.Add("@Otp", SqlDbType.VarChar).Value = otp;

            string email = string.Empty;
            using (SqlDataReader readerLabelDetails = ifExists.ExecuteReader())
            {
                if (readerLabelDetails.Read())
                {
                    email = readerLabelDetails.GetString(0);
                }
            }

            db.closeConnection();

            return email;
        }



    }
}
