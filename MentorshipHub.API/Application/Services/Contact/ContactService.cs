using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.Interfaces.Contact;
using MentorshipHub.API.Application.Interfaces.Email;

namespace MentorshipHub.API.Application.Services.Contact
{
    public class ContactService : IContactService
    {
        private readonly IEmailService _emailService;

        public ContactService(IEmailService emailService)
        {
            _emailService = emailService;
        }

        public async Task<ContactUsResponse> ProcessContactRequest(ContactUsRequest request)
        {
            bool customerResponse = await SendCustomerConfirmation(request);
            bool supportResponse = await SendSupportEmail(request);

            if(customerResponse && supportResponse)
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
            string to = request.Email;
            string subject = "We received your request";
            string body = $"Hi {request.FullName},\n\nThank you for contacting us. Our team will respond soon.";

            return await _emailService.SendEmail(to, subject, body);

        }

        private async Task<bool> SendSupportEmail(ContactUsRequest request)
        {
            string to = "support@xqare.in";
            string subject = "New Contact Request";
            string body = $"Name: {request.FullName}\nEmail: {request.Email}\nMessage: {request.Message}";

            return await _emailService.SendEmail(to, subject, body);

            
        }
    }
}
