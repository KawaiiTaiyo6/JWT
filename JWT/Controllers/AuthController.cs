using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly IEmailService _emailService;

        public AuthController(IConfiguration configuration, IUserService userService, IEmailService emailService)
        {
            _configuration = configuration;
            _userService = userService;
            _emailService = emailService;
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Password complexity validation
            if (model.Password.Length < 8)
            {
                return BadRequest(new { Message = "Пароль должен быть длиной не менее 8 символов." });
            }

            if (!model.Password.Any(char.IsUpper))
            {
                return BadRequest(new { Message = "Пароль должен содержать хотя бы одну заглавную букву" });
            }

            if (!model.Password.Any(char.IsLower))
            {
                return BadRequest(new { Message = "Пароль должен содержать хотя бы одну строчную букву." });
            }

            if (!model.Password.Any(char.IsDigit))
            {
                return BadRequest(new { Message = "Пароль должен содержать хотя бы одну цифру" });
            }

            if (!model.Password.Any(ch => !char.IsLetterOrDigit(ch)))
            {
                return BadRequest(new { Message = "Пароль должен содержать хотя бы один специальный символ" });
            }

            try
            {
                _userService.Register(model.Username, model.Password, model.Email);
                return Ok(new { Message = "Пользователь успешно зарегистрирован" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (!_userService.Authenticate(model.Username, model.Password))
            {
                return Unauthorized(new { Message = "Неверное имя пользователя или пароль" });
            }

            var token = GenerateJwtToken(model.Username);
            return Ok(new { Token = token });
        }

        [HttpPost("forgot-password")]
        public IActionResult ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                var resetToken = _userService.GeneratePasswordResetToken(model.Email);
                var resetLink = $"{_configuration["App:BaseUrl"]}/reset-password?token={resetToken}";

                _emailService.SendPasswordResetEmail(model.Email, resetLink);

                return Ok(new { Message = "Ссылка для сброса пароля была отправлена ​​на ваш адрес электронной почты." });
            }
            catch (Exception ex)
            {
                // Don't reveal whether the email exists or not
                return Ok(new { Message = "Если адрес электронной почты существует, ссылка для сброса была отправлена." });
            }
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword([FromBody] ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                _userService.ResetPassword(model.Token, model.NewPassword);
                return Ok(new { Message = "Пароль успешно сброшен" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
        };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // Models
    public class LoginModel
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }

    public class RegisterModel
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string Password { get; set; }

        [EmailAddress]
        public string Email { get; set; }
    }

    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }

    public class ResetPasswordModel
    {
        [Required]
        public string Token { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string NewPassword { get; set; }
    }

    // Services
    public interface IUserService
    {
        bool Authenticate(string username, string password);
        void Register(string username, string password, string email);
        string GeneratePasswordResetToken(string email);
        void ResetPassword(string token, string newPassword);
    }

    public class UserService : IUserService
    {
        private readonly Dictionary<string, (string Password, string Email)> _users = new();
        private readonly Dictionary<string, (string Username, DateTime Expiry)> _resetTokens = new();
        private readonly TimeSpan _tokenExpiry = TimeSpan.FromHours(1);

        public bool Authenticate(string username, string password)
        {
            return _users.ContainsKey(username) && _users[username].Password == password;
        }

        public void Register(string username, string password, string email)
        {
            if (_users.ContainsKey(username))
            {
                throw new Exception("Имя пользователя уже существует");
            }

            if (_users.Values.Any(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase)))
            {
                throw new Exception("Электронная почта уже зарегистрирована");
            }

            _users[username] = (password, email);
        }

        public string GeneratePasswordResetToken(string email)
        {
            var user = _users.FirstOrDefault(u => u.Value.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
            if (user.Key == null)
            {
                throw new Exception("Электронная почта не найдена");
            }

            var token = Guid.NewGuid().ToString();
            _resetTokens[token] = (user.Key, DateTime.UtcNow.Add(_tokenExpiry));

            return token;
        }

        public void ResetPassword(string token, string newPassword)
        {
            if (!_resetTokens.TryGetValue(token, out var tokenInfo))
            {
                throw new Exception("Недействительный токен");
            }

            if (tokenInfo.Expiry < DateTime.UtcNow)
            {
                _resetTokens.Remove(token);
                throw new Exception("Срок действия токена истек");
            }

            var username = tokenInfo.Username;
            if (!_users.ContainsKey(username))
            {
                throw new Exception("Пользователь не найден");
            }

            var user = _users[username];
            _users[username] = (newPassword, user.Email);
            _resetTokens.Remove(token);
        }
    }

    public interface IEmailService
    {
        void SendPasswordResetEmail(string email, string resetLink);
    }

    public class EmailService : IEmailService
    {
        public void SendPasswordResetEmail(string email, string resetLink)
        {
            Console.WriteLine($"Отправка письма для сброса пароля на адрес {email}");
            Console.WriteLine($"Сбросить ссылку: {resetLink}");
        }
    }

    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            var username = User.Identity.Name;
            return Ok(new { Message = $"Привет, {username}!" });
        }
    }
}
