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

        

        


        

        



        //move to helper
       

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

        


        public void executeQuery(string query)
        {
            SqlCommand getLabelDetails = new SqlCommand(query, Connection);
            getLabelDetails.ExecuteNonQuery();

        }


       


    }
}
