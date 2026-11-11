using FluentValidation;
using Xqare.Api.Application.DTO.Auth;
using Xqare.Api.Application.DTO.Rbac;

namespace Xqare.Api.Application.Validators;

/// <summary>
/// FluentValidation rules for request DTOs introduced by the MFA recovery and
/// role-management endpoints. These complement the existing DataAnnotations
/// rules and ensure the API action filter applies consistent server-side checks.
/// </summary>
public sealed class MfaAccountRecoveryRequestValidator : AbstractValidator<MfaAccountRecoveryRequest>
{
    public MfaAccountRecoveryRequestValidator()
    {
        RuleFor(x => x.Email)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .EmailAddress()
            .MaximumLength(256);

        RuleFor(x => x.Password)
            .MaximumLength(128);
    }
}

public sealed class MfaAccountRecoveryVerifyRequestValidator : AbstractValidator<MfaAccountRecoveryVerifyRequest>
{
    public MfaAccountRecoveryVerifyRequestValidator()
    {
        RuleFor(x => x.Email)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .EmailAddress()
            .MaximumLength(256);

        RuleFor(x => x.OtpCode)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .Matches(@"^\d{6}$");
    }
}

public sealed class MfaAccountRecoveryCompleteRequestValidator : AbstractValidator<MfaAccountRecoveryCompleteRequest>
{
    public MfaAccountRecoveryCompleteRequestValidator()
    {
        RuleFor(x => x.RecoveryGrant)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MinimumLength(32)
            .MaximumLength(128);

        RuleFor(x => x.Code)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .Matches(@"^\d{6}$");
    }
}

public sealed class MfaAccountRecoveryEnrollmentStartRequestValidator : AbstractValidator<MfaAccountRecoveryEnrollmentStartRequest>
{
    public MfaAccountRecoveryEnrollmentStartRequestValidator()
    {
        RuleFor(x => x.RecoveryGrant)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MinimumLength(32)
            .MaximumLength(128);
    }
}

public sealed class MfaAccountRecoveryExternalStartRequestValidator : AbstractValidator<MfaAccountRecoveryExternalStartRequest>
{
    public MfaAccountRecoveryExternalStartRequestValidator()
    {
        RuleFor(x => x.EmailProof)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MinimumLength(32)
            .MaximumLength(128);
    }
}

public sealed class DisconnectExternalLoginRequestValidator : AbstractValidator<DisconnectExternalLoginRequest>
{
    public DisconnectExternalLoginRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MaximumLength(128);
    }
}

public sealed class CreateRoleRequestValidator : AbstractValidator<CreateRoleRequest>
{
    public CreateRoleRequestValidator()
    {
        RuleFor(x => x.Name)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MinimumLength(2)
            .MaximumLength(80);

        RuleFor(x => x.Code)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .Matches(@"^[A-Za-z][A-Za-z0-9_]{1,49}$");

        RuleFor(x => x.PermissionCodes)
            .Must(codes => codes is null || codes.Count <= 200);

        RuleForEach(x => x.PermissionCodes)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MaximumLength(100);
    }
}

public sealed class UpdateRoleRequestValidator : AbstractValidator<UpdateRoleRequest>
{
    public UpdateRoleRequestValidator()
    {
        RuleFor(x => x.Name)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MinimumLength(2)
            .MaximumLength(80);
    }
}

public sealed class RoleAssignmentRequestValidator : AbstractValidator<RoleAssignmentRequest>
{
    public RoleAssignmentRequestValidator()
    {
        RuleFor(x => x.UserId).NotEmpty();
        RuleFor(x => x.RoleId).NotEmpty();
    }
}

public sealed class SetRolePermissionsRequestValidator : AbstractValidator<SetRolePermissionsRequest>
{
    public SetRolePermissionsRequestValidator()
    {
        RuleFor(x => x.PermissionCodes)
            .Must(codes => codes is null || codes.Count <= 200);

        RuleForEach(x => x.PermissionCodes)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MaximumLength(100);
    }
}
