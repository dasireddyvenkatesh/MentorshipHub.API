using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.Interfaces.Contact;
using Microsoft.AspNetCore.Mvc;

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

        [HttpPost]
        public IActionResult ContactUs(ContactUsRequest request)
        {
            var response = _contactService.ProcessContactRequest(request);

            return Ok(response);
        }
    }
}
