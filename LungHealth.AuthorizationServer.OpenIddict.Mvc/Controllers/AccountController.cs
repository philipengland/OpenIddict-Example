
using System.Security.Claims;
using LungHealth.AuthorizationServer.OpenIddict.Data;
using LungHealth.AuthorizationServer.OpenIddict.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace LungHealth.AuthorizationServer.OpenIddict.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            ViewData["ReturnUrl"] = model.ReturnUrl;

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.EmailAddress);
                if (user == null)
                {
                    model.ErrorMessage = "Error! You are stupid";
                    return View(model);
                }

                var signinResult = await _signInManager.PasswordSignInAsync(user, model.Password, false, true);
                if (signinResult.Succeeded == false)
                {
                    model.ErrorMessage = "Error! You are stupid";
                    return View(model);
                }
                
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, model.EmailAddress),
                    new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                    new Claim(ClaimTypes.Email, user.EmailAddress),
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

             //   await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            ViewData["ReturnUrl"] = model.ReturnUrl;

            if (ModelState.IsValid == false) return View(model);

            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user != null)
            {
                model.ErrorMessages.Add("Already exists, mate");
                return View(model);
            }

            user = new ApplicationUser()
            {
                UserName = model.EmailAddress,
                Email = model.EmailAddress,
                PhoneNumber = model.PhoneNumber
            };

            var identityResult = await _userManager.CreateAsync(user, model.Password);
            if(identityResult.Succeeded == false)
            {
                foreach (var error in identityResult.Errors)
                {
                    model.ErrorMessages.Add(error.Description);
                }
              
                return View(model);
            }
                
            return RedirectToAction(nameof(AccountController.ConfirmRegister), "Account");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmRegister()
        {
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
