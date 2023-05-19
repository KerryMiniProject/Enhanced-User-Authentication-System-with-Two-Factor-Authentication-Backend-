namespace AuthSA.Util
{
    using AuthSA.Model;
    using System;
    using System.Security.Cryptography;

    public class PasswordHasher
    {
        Database db = new Database();
        public string HashPassword(User user)
        {
            string? salt = GetSalt(user);

            // Convert the salt string back into a byte array
            byte[] saltBytes = Convert.FromBase64String(salt);

            // Hash the password using PBKDF2
            int iterations = 10000; // Number of iterations
            byte[] hashBytes = GetPbkdf2Bytes(user.Password, saltBytes, iterations, 32); // 32 is the desired hash length in bytes

            // Combine the salt and hash bytes into a single string
            byte[] hashWithSaltBytes = new byte[saltBytes.Length + hashBytes.Length];
            Array.Copy(saltBytes, 0, hashWithSaltBytes, 0, saltBytes.Length);
            Array.Copy(hashBytes, 0, hashWithSaltBytes, saltBytes.Length, hashBytes.Length);

            string hashedPassword = Convert.ToBase64String(hashWithSaltBytes);

            return hashedPassword;
        }

        public string? GetSalt(User user)
        {
            db.startConnection();
            db.openConnection();

            // Check if user exists, if exists get the salt from db
            string? salt = db.executeProcedureGetSalt(user);

            // If user does not exist then generate random salt
            if (string.IsNullOrEmpty(salt))
            {
                byte[] saltBytes = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(saltBytes);
                }

                salt = Convert.ToBase64String(saltBytes);

                // Consider storing the newly generated salt in the database for future use
            }

            db.closeConnection();

            return salt;
        }


        public bool VerifyPassword(string password, string hashedPassword)
        {
            // Convert the hashed password string back to bytes
            byte[] hashWithSaltBytes = Convert.FromBase64String(hashedPassword);

            // Get the salt from the hashed password bytes
            byte[] salt = new byte[16];
            Array.Copy(hashWithSaltBytes, 0, salt, 0, salt.Length);

            // Compute the hash of the provided password
            int iterations = 10000; // Number of iterations
            byte[] hashBytes = GetPbkdf2Bytes(password, salt, iterations, 32); // 32 is the desired hash length in bytes

            // Compare the computed hash with the stored hash
            bool isValid = CompareByteArrays(hashBytes, 0, hashWithSaltBytes, salt.Length, hashBytes.Length);

            return isValid;
        }

        private byte[] GetPbkdf2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                return pbkdf2.GetBytes(outputBytes);
            }
        }

        private bool CompareByteArrays(byte[] array1, int offset1, byte[] array2, int offset2, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (array1[offset1 + i] != array2[offset2 + i])
                {
                    return false;
                }
            }
            return true;
        }
    }

}
