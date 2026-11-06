using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MentorshipHub.API.Presentation.Filters;

/// <summary>
/// Runs the registered FluentValidation validator for each action argument before
/// a controller action executes. DataAnnotations remain supported for legacy DTOs.
/// </summary>
public sealed class FluentValidationActionFilter(IServiceProvider requestServices)
    : IAsyncActionFilter, IOrderedFilter
{
    // Run before the automatic [ApiController] model-state filter so FluentValidation
    // failures are included in the same 400 response as binding/DataAnnotations errors.
    public int Order => -3000;

    public async Task OnActionExecutionAsync(
        ActionExecutingContext context,
        ActionExecutionDelegate next)
    {
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
                continue;

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            if (requestServices.GetService(validatorType) is not IValidator validator)
                continue;

            var validationContext = new ValidationContext<object>(argument);
            var result = await validator.ValidateAsync(
                validationContext,
                context.HttpContext.RequestAborted);

            foreach (var error in result.Errors)
            {
                // DataAnnotations may already have reported the same field error.
                // Avoid duplicate messages while retaining additional FluentValidation rules.
                if (context.ModelState.TryGetValue(error.PropertyName, out var existing) &&
                    existing.Errors.Count > 0)
                {
                    continue;
                }

                context.ModelState.AddModelError(error.PropertyName, error.ErrorMessage);
            }
        }

        if (!context.ModelState.IsValid)
        {
            var details = new ValidationProblemDetails(context.ModelState)
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "One or more validation errors occurred."
            };
            context.Result = new BadRequestObjectResult(details);
            return;
        }

        await next();
    }
}
