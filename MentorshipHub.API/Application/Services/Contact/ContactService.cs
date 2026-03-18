using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.Interfaces.Contact;
using MentorshipHub.API.Application.Interfaces.Email;
using System.Text;

namespace MentorshipHub.API.Application.Services.Contact
{
    public class ContactService : IContactService
    {
        private readonly IEmailService _emailService;
        private readonly IEmailTemplateService _emailTemplateService;

        public ContactService(IEmailService emailService, IEmailTemplateService emailTemplateService)
        {
            _emailService = emailService;
            _emailTemplateService = emailTemplateService;
        }

        public async Task<ContactUsResponse> ProcessContactRequest(ContactUsRequest request)
        {
            bool customerResponse = await SendCustomerConfirmation(request);
            bool supportResponse = await SendSupportEmail(request);

            if (customerResponse && supportResponse)
            {
                return new ContactUsResponse
                {
                    IsSuccess = true,
                    Message = "Your message has been sent successfully. We will get back to you shortly"
                };
            }

            return new ContactUsResponse
            {
                IsSuccess = false,
                Message = "Can you please try again after sometime"
            };
        }

        private async Task<bool> SendCustomerConfirmation(ContactUsRequest request)
        {
            var response = _emailTemplateService.ContactUsCustomerTemplate(request.FullName);

            return await _emailService.SendEmail(request.Email, response.subject, response.body);

        }

        private async Task<bool> SendSupportEmail(ContactUsRequest request)
        {
            string email = "support@xqare.in";

            var response = _emailTemplateService.ContactUsSupportTemplate(request.FullName, request.Email, request.Subject, request.Message);

            return await _emailService.SendEmail(email, response.subject, response.body);


        }
    }
}
