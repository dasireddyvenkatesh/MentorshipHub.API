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

            return Ok(refreshToken);
        }
    }
}
