namespace AuthSA.Service
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;
    using Microsoft.IdentityModel.Tokens;

    public class TokenService
    {
        private readonly string _secretKey = "abcdefghijklmnopqrstuvwxyz";


        public string GenerateAccessToken(string userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("user_id", userId) }),
                Expires = DateTime.UtcNow.AddMinutes(15),  // Expiration time for the access token
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            //string accessToken = tokenHandler.WriteToken(token);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken(string userId = null)
        {
            var refreshToken = Guid.NewGuid().ToString();
            // You may want to store the refresh token in a secure data store or database
            // associating it with the user for future validation and revocation
            return refreshToken;
        }

        public ClaimsPrincipal ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secretKey);
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            };
            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch (Exception)
            {
                return null; // Token validation failed
            }
        }
    }

    

}
