using System.ComponentModel.DataAnnotations;

namespace LungHealth.AuthorizationServer.OpenIddict.ViewModels
{
    public class RegisterViewModel
    {
        [EmailAddress(ErrorMessage = "You must provide a valid Email Address")]
        [Required(ErrorMessage="You must provide an Email Address")]
        public string EmailAddress { get; set; }

        [Required(ErrorMessage = "You must enter a password")]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string RepeatPassword { get; set; }

        [Phone(ErrorMessage = "You must provide a valid Phone Number")]
        [Required(ErrorMessage = "You must provide a Phone Number")]
        public string PhoneNumber { get; set; }

        public string? ReturnUrl { get; set; }

        public IList<string>? ErrorMessages { get; set; } = new List<string>();
    }
}
