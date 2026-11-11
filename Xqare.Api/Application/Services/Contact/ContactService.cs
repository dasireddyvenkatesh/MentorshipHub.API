using Xqare.Api.Application.DTO.ContactUs;
using Xqare.Api.Constants.Messages;
using Xqare.Api.Application.Interfaces.Contact;
using Xqare.Api.Application.Interfaces.Email;
using System.Text;

namespace Xqare.Api.Application.Services.Contact
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
                    Message = ContactMessages.Sent
                };
            }

            return new ContactUsResponse
            {
                IsSuccess = false,
                Message = ContactMessages.SendFailed
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
