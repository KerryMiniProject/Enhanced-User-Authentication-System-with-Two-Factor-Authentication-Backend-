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

        public string? executeProcedureGetSalt(User user)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetSalt  @Email", db.Connection);
            SqlParameter email = new SqlParameter("@Email", SqlDbType.NVarChar);
            ifExists.Parameters.Add(email);
            ifExists.Parameters["@email"].Value = user.Email;
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
