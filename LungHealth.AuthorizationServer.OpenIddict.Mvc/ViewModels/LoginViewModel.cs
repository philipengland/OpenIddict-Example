using System.ComponentModel.DataAnnotations;

namespace LungHealth.AuthorizationServer.OpenIddict.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        public string Password { get; set; }
        public string? ReturnUrl { get; set; }

        public string? ErrorMessage { get; set; }
    }
}
