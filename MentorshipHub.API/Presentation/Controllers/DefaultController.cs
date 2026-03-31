using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.Controllers
{
    [Route("/")]
    [ApiController]
    public class DefaultController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            string refreshToken = Request.Cookies["refreshToken"] ?? default!;

            string jwtToken = Request.Cookies["jwtToken"] ?? default!;

            var result = (jwtToken, refreshToken);

            return Ok(result);
        }
    }
}
