
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using ogani_master.Models;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace ogani_master.FIlters
{
    public class Authenticate : ActionFilterAttribute
    {
        private readonly OganiMaterContext _dbContext;

        public Authenticate(OganiMaterContext dbContext)
        {
            _dbContext = dbContext;
        }


        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {

            HttpContext httpContext = context.HttpContext;

            int? userId = httpContext.Session.GetInt32("UserID");

            List<FavoritesModel> favorites = await this._dbContext.Favorites.Include(f => f.Product).Where(f => f.UserID == userId).ToListAsync();

            User? currentUser = await this._dbContext.users.FirstOrDefaultAsync(u => u.UserId == userId);
            string? jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET");
            string? HASH_MESSAGE_SECRET_KEY = Environment.GetEnvironmentVariable("HASH_MESSAGE_SECRET_KEY");
            string? PUBLIC_SIGNATURE_CLIENT_ID = Environment.GetEnvironmentVariable("PUBLIC_SIGNATURE_CLIENT_ID");

            if (jwtSecret == null) throw new Exception("The JWT_SECRET is not empty");
            if (HASH_MESSAGE_SECRET_KEY == null) throw new Exception("The HASH_MESSAGE_SECRET_KEY is not empty");
            if (PUBLIC_SIGNATURE_CLIENT_ID == null) throw new Exception("The PUBLIC_SIGNATURE_CLIENT_ID is not empty");

            if (context.Controller is Controller controller)
            {

                if(currentUser != null)
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(jwtSecret);
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new[]
                        {
                    new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()!)
                }),
                        Expires = DateTime.UtcNow.AddDays(7),
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(key),
                            SecurityAlgorithms.HmacSha256Signature
                        )
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var tokenString = tokenHandler.WriteToken(token);

                    controller.ViewBag.isLogin = true;
                    controller.ViewBag.JwtSecret = jwtSecret;
                    controller.ViewBag.Token = "Bearer " + tokenString;
                    controller.ViewBag.HASH_MESSAGE_SECRET_KEY = HASH_MESSAGE_SECRET_KEY;
                    controller.ViewBag.PUBLIC_SIGNATURE_CLIENT_ID = PUBLIC_SIGNATURE_CLIENT_ID;
                }

                controller.ViewBag.CurrentUser = currentUser;
                controller.ViewBag.Favorites = favorites;
            }

            await next();
        }
    }
}
