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
//            string hashed = passwordHasher.HashPassword(user);
//            user.Password = hashed;
//            string? salt = passwordHasher.GetSalt(user);
//            db.insertIntoPasswordTable(user, salt);
//            db.insertIntoUserTable(user);

//            db.closeConnection();
//            return response.badAuth();
//        }
//    }
//}
