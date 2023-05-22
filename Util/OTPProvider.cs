using AuthSA.Model;
using Newtonsoft.Json;
using System.Text;
using Twilio;
using Twilio.Rest.Api.V2010.Account;


namespace AuthSA.Util
{
    public class OTPProvider 
    {
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


        public async Task<OtpVerificationJsonResponseKerry> VerifyOTP(OtpVerificationRequestBody otpVerificationRequestBody)
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
                // Todo: Handle the error based on your requirements
                throw new Exception($"The request failed with status code: {response.StatusCode}");
            }
        }

        public string? sendOTP(string phoneNumber)
        {
            string accountSid = "AC5c20008228cdd9647c8389720321552f";
            string authToken = "e7ad784b49b4d412449ca1b339e164f4";
            TwilioClient.Init(accountSid, authToken);
            Random random = new Random();
            int otp = random.Next(1000, 9999);
            string otpString = otp.ToString(); // Replace with the recipient's phone number
            string message = $"Your OTP is: {otpString}";


            var smsMessage = MessageResource.Create(
                body: message,
                from: new Twilio.Types.PhoneNumber("+12545406624"),
                to: new Twilio.Types.PhoneNumber(phoneNumber)
            );
            return otpString;


        }

        public bool verifyOTP(string UserOtp, string ServerOtp)
        {
            return UserOtp.Equals(ServerOtp);
        }

    }
}
