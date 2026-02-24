using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost("/login")]
        public IActionResult Login(LoginRequest loginRequest)
        {
            LoginResponse loginResponse = new LoginResponse
            {
                IsSuccess = true,
                RequiresMfa = true,
                Token = "dummy-jwt",
                Ipaddress = HttpContext.Request.Headers["X-Forwarded-For"].ToString()
            };
            return Ok(loginResponse);
        }


        public class LoginRequest
        {
            public string Email { get; set; }
            public string Password { get; set; }
        }

        public class LoginResponse
        {
            public bool IsSuccess { get; set; }
            public bool RequiresMfa { get; set; }
            public string Token { get; set; }
            public string Ipaddress { get; set; }
        }
    }
}
