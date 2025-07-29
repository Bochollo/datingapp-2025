using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Extensions;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(AppDBContext context, ITokenService tokenService) : BaseAPIController
{
    [HttpPost("register")] // api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        // Check if email is used by another user
        if (await EmailExists(registerDto.Email)) return BadRequest("Email already exists");

        // set necessary fields and create the hashes for it.
        using var hmac = new HMACSHA512();
        var user = new AppUser
        {
            DisplayName = registerDto.DisplayName,
            Email = registerDto.Email,
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        // create the user with the given parameters
        context.Users.Add(user);
        await context.SaveChangesAsync();
        return user.ToDto(tokenService);
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        // success if exactly one user with the given email exists in database
        var user = await context.Users.SingleOrDefaultAsync(x => x.Email == loginDto.Email);
        // otherwise return error
        if (user == null) return Unauthorized("Invalid email adress");

        // calculate Hash with database PasswordSalt and given password
        using var hmac = new HMACSHA512(user.PasswordSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
        // compare computed PasswordHash with database PasswordHash
        for (var i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
        }

        return user.ToDto(tokenService);

    }

    private async Task<bool> EmailExists(string email)
    {
        // check if email address already exists
        return await context.Users.AnyAsync(x => x.Email.ToLower() == email.ToLower());
    }




}
