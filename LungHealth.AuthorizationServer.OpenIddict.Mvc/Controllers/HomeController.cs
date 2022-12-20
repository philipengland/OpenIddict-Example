using Microsoft.AspNetCore.Mvc;

namespace LungHealth.AuthorizationServer.OpenIddict.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}