using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CoreTest_WebApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CoreTest_WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private UserManager<ApplicationUser> _userManager;
        public UserProfileController(UserManager<ApplicationUser> userManager) {

            _userManager = userManager;
        }


        [HttpGet]
        [Authorize]
        //[Route("Register")]
        //POST
        public async Task<object> GetUserProfile()
        {
            string userId = User.Claims.First(m => m.Type == "UserID").Value;
            var user = await _userManager.FindByIdAsync(userId);

            return new
            {

                user.FullName,
                user.Email,
                user.UserName
            };
        }

        [HttpGet]
        [Authorize(Roles ="Admin")]
        [Route("ForAdmin")]
     
        public string GetForAdmin()
        {

            return "Admin Only";
        }

        [HttpGet]
        [Authorize(Roles = "Customer")]
        [Route("ForCustomer")]

        public string GetForCustomer()
        {

            return "Customer Only";
        }

    }
}