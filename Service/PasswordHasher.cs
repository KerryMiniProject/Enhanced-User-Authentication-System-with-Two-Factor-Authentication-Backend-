namespace AuthSA.Util
{
    using AuthSA.Model;
    using AuthSA.Service.Database;
    using System;
    using System.Security.Cryptography;

    public class PasswordHasher
    {
        Database db = new Database();
        Procedure procedure = new Procedure();
        public string HashPassword(User user)
        {
            db.startConnection();
            db.openConnection();
            string? salt = GetSalt(user.Email, user.PhoneNo);

            //check if salt exists in db if not then store otherwise store it
            bool ifExist = procedure.executeProcedureCheckIfSaltExists(user.PhoneNo, user.Email);
            

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
            user.Password = hashedPassword;
            if (!ifExist)
            {
                procedure.insertIntoPasswordTable(user, salt);
            }
            db.closeConnection();
            return hashedPassword;
        }

        public string? GetSalt(string email = null, string phoneNo = null, bool generateNewSalt = true)
        {
            db.startConnection();
            db.openConnection();

            // Check if user exists, if exists get the salt from db
            string? salt = procedure.executeProcedureGetSalt(email, phoneNo);

            // If user does not exist then generate random salt only if generateNewSalt is true
            if (string.IsNullOrEmpty(salt) && generateNewSalt)
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


        public bool VerifyPassword(string password, string email = null, string phoneNo = null)
        {
            db.startConnection();
            db.openConnection();
            //hash whats entered and compare it to the one in db
            string hashed = HashPassword(new User() { Email = email, Password = password, PhoneNo = phoneNo });

            string? passwordFromDb = procedure.executeProcedureGetPassword(email,phoneNo);  //get from db using email, phoneNo
            db.closeConnection();
            return passwordFromDb == hashed;
           
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
            if (array1.Length != array2.Length - offset2 + offset1)
            {
                return false;
            }

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
