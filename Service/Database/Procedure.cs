using AuthSA.Model;
using AuthSA.Util;
using System.Data;
using System.Data.SqlClient;

namespace AuthSA.Service.Database
{
    public class Procedure
    {
        Utility util = new Utility();
        Database db = new Database();
        public void insertIntoPasswordTable(User user, string salt)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO Password(Email, Phone_No, CurrentPassword, Salt) values (N'{user.Email.ToLower()}', N'{user.PhoneNo}',N'{user.Password}', N'{salt}')", db.Connection);
            getLabelDetails.ExecuteNonQuery();
            db.closeConnection();
        }

        //public void insertSaltIntoPasswordTable(User user, string salt)
        //{
        //    db.startConnection();
        //    db.openConnection();
        //    SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO Password(Email, Phone_No, Salt) values (N'{user.Email.ToLower()}', N'{user.PhoneNo}', N'{salt}')", db.Connection);
        //    getLabelDetails.ExecuteNonQuery();
        //    db.closeConnection();
        //}

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
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO UserTable(First_Name, Last_Name, Email, Phone_No) values (N'{user.FirstName}', N'{user.LastName}',N'{user.Email.ToLower()}', N'{user.PhoneNo}')", db.Connection);
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


        public bool executeProcedureVerifyEmailOtp(string guid, string otp, string email)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckOtpEmail  @Guid, @Email, @Otp", db.Connection);
            SqlParameter guidparameter = new SqlParameter("@Guid", SqlDbType.VarChar);
            SqlParameter emailParameter = new SqlParameter("@Email", SqlDbType.NVarChar);
            SqlParameter otpparameter = new SqlParameter("@Otp", SqlDbType.VarChar);
            ifExists.Parameters.Add(guidparameter);
            ifExists.Parameters.Add(otpparameter);
            ifExists.Parameters.Add(emailParameter);
            ifExists.Parameters["@Guid"].Value = guid;
            ifExists.Parameters["@Email"].Value = email;
            ifExists.Parameters["@Otp"].Value = otp;
            ifExists.ExecuteNonQuery();
            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
            db.closeConnection();
            string resultLowerCase = result.ToLower();
            bool resultBool = Convert.ToBoolean(resultLowerCase);
            return resultBool;
        }

    }
}
