using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.Interfaces.Contact;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;

namespace MentorshipHub.API.Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContactusController : ControllerBase
    {
        private readonly IContactService _contactService;
        public ContactusController(IContactService contactService)
        {
            _contactService = contactService;
        }

        [AllowAnonymous]
        [HttpPost]
        [EnableRateLimiting("contact-us-ip")]
        public async Task<IActionResult> ContactUs(ContactUsRequest request)
        {
            var response = await _contactService.ProcessContactRequest(request);

            return Ok(response);
        }
    }
}
