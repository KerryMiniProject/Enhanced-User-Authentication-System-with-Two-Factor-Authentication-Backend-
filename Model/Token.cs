namespace AuthSA.Model
{
    public class Token
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }

    public class AccessToken
    {
        public string? accessToken { get; set; }
    }
}
