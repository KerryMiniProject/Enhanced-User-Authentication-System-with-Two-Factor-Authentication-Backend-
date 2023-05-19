//using AuthSA.Model;

//namespace AuthSA.Util
//{
//    public class Auth
//    {
//        Database db = new Database();
//        PasswordHasher passwordHasher = new PasswordHasher();   
//        public JsonResponse SignUp(User user)
//        {
//            JsonResponse response = new JsonResponse();
//            db.startConnection();
//            db.openConnection();


//            //verify otp
//            bool ifExists = db.executeProcedureVerifyOtp(user.OtpVerify.Guid, user.OtpVerify.Otp, user.PhoneNo);
//            if (ifExists)
//            {
//                string hashed = passwordHasher.HashPassword(user);
//                user.Password = hashed;
//                string? salt = passwordHasher.GetSalt(user);
//                db.insertIntoPasswordTable(user, salt);
//                db.insertIntoUserTable(user);
//                return response.success();
//            }
//            db.closeConnection();
//            return response.badAuth();
//        }
//    }
//}
