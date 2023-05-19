using AuthSA.Model;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Net.Mail;
using System.Net;
using System.Text.RegularExpressions;

namespace AuthSA.Util
{
    public class Database
    {
        public string ConnectionString = @$"Server=10.112.85.214\SQLEXPRESS, 10433;Database=KE_Mini;User Id=internship;Password=vGDjCJ6UA6kcerkY;Connect Timeout=30;TrustServerCertificate=True;";
        public SqlConnection? Connection;


        public void startConnection()
        {
            Connection = new SqlConnection(ConnectionString);
        }
        public SqlConnection? getConnection()
        {
            return Connection;
        }

        public string getConnectionString()
        {
            return ConnectionString;
        }

        public void closeConnection()
        {
            Connection.Close();
        }

        public void openConnection()
        {
            Connection.Open();
        }

        public void insertIntoUserTable(User user)
        {
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO UserTable(FirstName, LastName, Email, PhoneNo) values (N'{user.FirstName}', N'{user.LastName}',N'{user.Email.ToLower()}', N'{user.PhoneNo}')", Connection);
            getLabelDetails.ExecuteNonQuery();
        }

        public void insertIntoOtpTable(string id, string otp, string phoneNo)
        {
            using (SqlCommand command = new SqlCommand("SELECT COUNT(*) FROM Otp WHERE PhoneNo = @phoneNo", Connection))
            {
                command.Parameters.AddWithValue("@phoneNo", phoneNo);

                int existingRows = (int)command.ExecuteScalar();

                if (existingRows == 0)
                {
                    SqlCommand insertCommand = new SqlCommand("INSERT INTO Otp(GUID, Otp, PhoneNo) VALUES (@id, @otp, @phoneNo)", Connection);
                    insertCommand.Parameters.AddWithValue("@id", id);
                    insertCommand.Parameters.AddWithValue("@otp", otp);
                    insertCommand.Parameters.AddWithValue("@phoneNo", phoneNo);
                    insertCommand.ExecuteNonQuery();
                }
                else
                {
                    SqlCommand updateCommand = new SqlCommand("UPDATE Otp SET GUID = @id, Otp = @otp WHERE PhoneNo = @phoneNo", Connection);
                    updateCommand.Parameters.AddWithValue("@id", id);
                    updateCommand.Parameters.AddWithValue("@otp", otp);
                    updateCommand.Parameters.AddWithValue("@phoneNo", phoneNo);
                    updateCommand.ExecuteNonQuery();
                }
            }
        }


        public void insertIntoPasswordTable(User user, string salt)
        {
            SqlCommand getLabelDetails = new SqlCommand($@"INSERT INTO PasswordTable(Email, HashPassword, Salt) values (N'{user.Email.ToLower()}', N'{user.Password}',N'{salt}')", Connection);
            getLabelDetails.ExecuteNonQuery();
        }

        public string? executeProcedureGetSalt(User user)
        {
            SqlCommand ifExists = new SqlCommand("EXEC dbo.GetSalt  @Email", Connection);
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
            return salt;
        }



        //move to helper
        public static bool IsValidEmail(string email)
        {
            // Regex pattern for email validation
            string pattern = @"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$";

            // Check if the email matches the pattern
            Match match = Regex.Match(email, pattern);

            // Return true if the email is valid, false otherwise
            return match.Success;
        }


            public static bool IsValidPhoneNumber(string phoneNumber)
            {
                // Check if the phone number is exactly 10 digits
                if (phoneNumber.Length != 10)
                {
                    return false;
                }

                // Check if the phone number contains only digits
                foreach (char digit in phoneNumber)
                {
                    if (!char.IsDigit(digit))
                    {
                        return false;
                    }
                }

                // If all criteria pass, the phone number is valid
                return true;
            }

        public string sendOTPEmail(User user)
        {
            Guid g = Guid.NewGuid();
            string guid = g.ToString();
            try
            {
                using (MailMessage mail = new MailMessage())
                {
                    mail.From = new MailAddress("kerex1234@gmail.com");
                    mail.To.Add(user.Email);
                    mail.Subject = "OTP Account";
                    mail.IsBodyHtml = true;
                    Random random = new Random();
                    int otp = random.Next(1000, 9999);
                    string otpString = otp.ToString();
                    string connectionString = getConnectionString();


                    string selectQuery = $"SELECT COUNT(*) FROM [dbo].[otpEmail] WHERE [Email] = '{user.Email}'";
                    SqlCommand selectCommand = new SqlCommand(selectQuery, Connection);
                    int emailCount = (int)selectCommand.ExecuteScalar();

                    if (emailCount > 0)
                    {
                        string updateQuery = $"UPDATE [dbo].[otpEmail] SET [GUID] = '{guid}', [OTP] = '{otpString}' WHERE [Email] = '{user.Email}'";
                        SqlCommand updateCommand = new SqlCommand(updateQuery, Connection);
                        updateCommand.ExecuteNonQuery();
                    }
                    else
                    {
                        string insertQuery = $"INSERT INTO [dbo].[otpEmail] ([GUID], [Email], [OTP]) VALUES ('{guid}', '{user.Email}', '{otpString}')";
                        SqlCommand insertCommand = new SqlCommand(insertQuery, Connection);
                        insertCommand.ExecuteNonQuery();
                    }
                    string body = $"<h1>Hello</h1><p>This is your OTP {otpString} </p><br><img src=\"cid:qrCodeImage\">";
                    AlternateView htmlView = AlternateView.CreateAlternateViewFromString(body, null, "text/html");
                    mail.AlternateViews.Add(htmlView);

                    // Send the email
                    var smtpClient = new SmtpClient("smtp.gmail.com")
                    {
                        Port = 587,
                        Credentials = new NetworkCredential("kerex1234@gmail.com", "ozyptkpymdssoxau"),
                        EnableSsl = true,
                    };

                    smtpClient.Send(mail);

                }
                return guid;
            }
            catch(Exception ex)
            {
                throw new Exception();
            }
        }

        public bool executeProcedureCheckIfUserExists(User user)
        {
            if (string.IsNullOrEmpty(user.Email) && string.IsNullOrEmpty(user.PhoneNo))
                throw new ArgumentException("Both Email and PhoneNo can't be null.");

            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfUserExists  @email, @phoneNum", Connection);

            ifExists.Parameters.AddWithValue("@email", (object)user.Email ?? DBNull.Value);
            ifExists.Parameters.AddWithValue("@phoneNum", (object)user.PhoneNo ?? DBNull.Value);

            if(user.Email!=null && !IsValidEmail(user.Email))
            {
                throw new Exception();
            }

            if(user.PhoneNo!= null && !IsValidPhoneNumber(user.PhoneNo))
            {
                throw new Exception();
            }

            SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
            string result = "";
            if (readerLabelDetails.Read())
            {
                result = readerLabelDetails[0].ToString();
            }
            readerLabelDetails.Close();
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

        //public bool executeProcedureCheckIfUserExists(User user)
        //{
        //    SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckIfUserExists  @email, @phoneNum", Connection);
        //    SqlParameter emailParameter = new SqlParameter("@email", SqlDbType.NVarChar);
        //    SqlParameter phoneNumParameter = new SqlParameter("@phoneNum", SqlDbType.NVarChar);

        //    ifExists.Parameters.Add(emailParameter);
        //    ifExists.Parameters.Add(phoneNumParameter);
        //    ifExists.Parameters["@email"].Value = user.Email;
        //    ifExists.Parameters["@phoneNum"].Value = user.PhoneNo;
        //    ifExists.ExecuteNonQuery();
        //    SqlDataReader readerLabelDetails = ifExists.ExecuteReader();
        //    string result = "";
        //    if (readerLabelDetails.Read())
        //    {
        //        result = readerLabelDetails[0].ToString();
        //    }
        //    readerLabelDetails.Close();
        //    string resultLowerCase = result.ToLower();
        //    bool resultBool = Convert.ToBoolean(resultLowerCase);
        //    return resultBool;
        //}

        public bool executeProcedureVerifyOtp(string guid, string otp, string phoneNo)
        {
            SqlCommand ifExists = new SqlCommand("EXEC dbo.CheckOtp  @Guid, @Otp, @PhoneNo", Connection);
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
            string resultLowerCase = result.ToLower();
            bool resultBool = Convert.ToBoolean(resultLowerCase);
            return resultBool;
        }


        public void executeQuery(string query)
        {
            SqlCommand getLabelDetails = new SqlCommand(query, Connection);
            getLabelDetails.ExecuteNonQuery();

        }


       


    }
}
