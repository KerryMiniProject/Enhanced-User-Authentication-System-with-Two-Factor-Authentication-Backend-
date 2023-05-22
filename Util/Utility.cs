using System.Text.RegularExpressions;

namespace AuthSA.Util
{
    public class Utility
    {

        public bool IsValidEmail(string email)
        {
            // Regex pattern for email validation
            string pattern = @"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$";

            // Check if the email matches the pattern
            Match match = Regex.Match(email, pattern);

            // Return true if the email is valid, false otherwise
            return match.Success;
        }


        public bool IsValidPhoneNumber(string phoneNumber)
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
    }
}
