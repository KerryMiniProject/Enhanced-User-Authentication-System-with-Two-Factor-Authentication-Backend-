using AuthSA.Model;
using Newtonsoft.Json;
using System.Data.SqlClient;
using System.Net.Mail;
using System.Net;
using System.Text;
using Twilio;
using Twilio.Rest.Api.V2010.Account;


namespace AuthSA.Util
{
    public class OTPProvider 
    {
        Utility util = new Utility();
        Database db = new Database();
        Procedure procedure = new Procedure();
       public async Task<JsonResponseFromKerry> SendOtpToPhoneHelper(string phoneNumber)
        {
            // Create HttpClient instance
            using (HttpClient client = new HttpClient())
            {
                // Set request headers
                client.DefaultRequestHeaders.Add("accept", "application/json");
                client.DefaultRequestHeaders.Add("AppID", "OTPService_Api");
                client.DefaultRequestHeaders.Add("AppKey", "BF2E74B7-F2FE-44D7-9816-8C8D20981444");

                // Send the POST request
                HttpResponseMessage response = await client.PostAsync($"https://poc-c2c.th.kerryexpress.com/otp-service/api/OTP/v1/OTP/{phoneNumber}", null);

                // Read the response content as JSON string
                string jsonResponse = await response.Content.ReadAsStringAsync();
                JsonResponseFromKerry? responseData = JsonConvert.DeserializeObject<JsonResponseFromKerry>(jsonResponse);

                // Check if the request was successful
                if (response.IsSuccessStatusCode)
                {
                    return responseData;
                }
                else //Todo: Handle the error
                {
                    return responseData;
                }
            }
        }


        public async Task<OtpVerificationJsonResponseKerry> VerifyOTP(OtpPhoneVerificationRequestBody otpVerificationRequestBody)
        {
            var httpClient = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Post, "https://poc-c2c.th.kerryexpress.com/otp-service/api/OTP/v1/OTP/Verify");
            request.Headers.Add("accept", "application/json");
            request.Headers.Add("AppID", "OTPService_Api");
            request.Headers.Add("AppKey", "BF2E74B7-F2FE-44D7-9816-8C8D20981444");



            request.Content = new StringContent(JsonConvert.SerializeObject(otpVerificationRequestBody), Encoding.UTF8, "application/json");

            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<OtpVerificationJsonResponseKerry>(responseBody);
            }
            else
            {
                throw new Exception($"The request failed with status code: {response.StatusCode}");
            }
        }

        public string sendOTPEmail(string email)
        {
            if(!util.IsValidEmail(email))
            {
                throw new Exception();
            }

            Guid g = Guid.NewGuid();
            string guid = g.ToString();
            db.startConnection();
            db.openConnection();
            try
            {
                using (MailMessage mail = new MailMessage())
                {
                    mail.From = new MailAddress("kerex1234@gmail.com");
                    mail.To.Add(email);
                    mail.Subject = "OTP Account";
                    mail.IsBodyHtml = true;
                    Random random = new Random();
                    int otp = random.Next(100000, 999999);
                    string otpString = otp.ToString();
                    string connectionString = db.getConnectionString();


                    string selectQuery = $"SELECT COUNT(*) FROM [dbo].[otpEmail] WHERE [Email] = '{email}'";
                    SqlCommand selectCommand = new SqlCommand(selectQuery, db.Connection);
                    int emailCount = (int)selectCommand.ExecuteScalar();

                    if (emailCount > 0)
                    {
                        string updateQuery = $"UPDATE [dbo].[otpEmail] SET [GUID] = '{guid}', [OTP] = '{otpString}' WHERE [Email] = '{email}'";
                        SqlCommand updateCommand = new SqlCommand(updateQuery, db.Connection);
                        updateCommand.ExecuteNonQuery();
                    }
                    else
                    {
                        string insertQuery = $"INSERT INTO [dbo].[otpEmail] ([GUID], [Email], [OTP]) VALUES ('{guid}', '{email}', '{otpString}')";
                        SqlCommand insertCommand = new SqlCommand(insertQuery, db.Connection);
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
                db.closeConnection();
                return guid;

            }
            catch (Exception)
            {
                db.closeConnection();
                throw new Exception();

            }
        }
    }
}
