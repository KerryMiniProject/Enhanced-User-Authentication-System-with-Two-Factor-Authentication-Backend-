﻿using AuthSA.Model;
using System.Data;
using System.Data.SqlClient;

namespace AuthSA.Util
{
    public class Procedure
    {
        Utility util = new Utility();
        Database db = new Database();
  
        public void insertIntoOtpTable(string id, string otp, string phoneNo)
        {
            db.startConnection();
            db.openConnection();
            using (SqlCommand command = new SqlCommand("SELECT COUNT(*) FROM Otp WHERE PhoneNo = @phoneNo", db.Connection))
            {
                command.Parameters.AddWithValue("@phoneNo", phoneNo);

                int existingRows = (int)command.ExecuteScalar();

                if (existingRows == 0)
                {
                    SqlCommand insertCommand = new SqlCommand("INSERT INTO Otp(GUID, Otp, PhoneNo) VALUES (@id, @otp, @phoneNo)", db.Connection);
                    insertCommand.Parameters.AddWithValue("@id", id);
                    insertCommand.Parameters.AddWithValue("@otp", otp);
                    insertCommand.Parameters.AddWithValue("@phoneNo", phoneNo);
                    insertCommand.ExecuteNonQuery();
                }
                else
                {
                    SqlCommand updateCommand = new SqlCommand("UPDATE Otp SET GUID = @id, Otp = @otp WHERE PhoneNo = @phoneNo", db.Connection);
                    updateCommand.Parameters.AddWithValue("@id", id);
                    updateCommand.Parameters.AddWithValue("@otp", otp);
                    updateCommand.Parameters.AddWithValue("@phoneNo", phoneNo);
                    updateCommand.ExecuteNonQuery();
                }
            }
            db.closeConnection();
        }

        public void insertIntoPasswordTable(User user, string salt)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO PasswordTable(Email, HashPassword, Salt) values (N'{user.Email.ToLower()}', N'{user.Password}',N'{salt}')", db.Connection);
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
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO UserTable(FirstName, LastName, Email, PhoneNo) values (N'{user.FirstName}', N'{user.LastName}',N'{user.Email.ToLower()}', N'{user.PhoneNo}')", db.Connection);
            getLabelDetails.ExecuteNonQuery();
            db.closeConnection();
        }

        public bool executeProcedureCheckIfUserExists(User user)
        {
            db.startConnection();
            db.openConnection();
            if (string.IsNullOrEmpty(user.Email) && string.IsNullOrEmpty(user.PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfUserExists  @email, @phoneNum", db.Connection);

            ifExists.Parameters.AddWithValue("@email", (object)user.Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@phoneNum", (object)user.PhoneNo ?? DBNull.Value);

            if (user.Email != null && !util.IsValidEmail(user.Email))
            {
                db.closeConnection();
                throw new Exception();
            }

            if (user.PhoneNo != null && !util.IsValidPhoneNumber(user.PhoneNo))
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

        public bool helperProcedureCheckUserExist(SqlCommand ifExists)
        {
            ifExists.ExecuteNonQuery();

            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";

            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }

            readerLabelDetails.Close();

            string resultLowerCase = result.ToLower();
            bool resultBool = Convert.ToBoolean(resultLowerCase);
            return resultBool;
        }

        public bool executeProcedureVerifyOtp(string guid, string otp, string phoneNo)
        {
            db.startConnection();
            db.openConnection();
            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckOtp  @Guid, @Otp, @PhoneNo", db.Connection);
            SqlParameter guidparameter = new SqlParameter("@Guid", SqlDbType.VarChar);
            SqlParameter otpparameter = new SqlParameter("@Otp", SqlDbType.VarChar);
            SqlParameter phoneNoParameter = new SqlParameter("@PhoneNo", SqlDbType.NVarChar);
            ifExists.Parameters.Add(guidparameter);
            ifExists.Parameters.Add(otpparameter);
            ifExists.Parameters.Add(phoneNoParameter);
            ifExists.Parameters["@Guid"].Value = guid;
            ifExists.Parameters["@Otp"].Value = otp;
            ifExists.Parameters["@PhoneNo"].Value = phoneNo;
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