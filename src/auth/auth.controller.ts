import { Controller, Get, Post, Body, UseGuards, Req } from '@nestjs/common';

import { Request } from 'express';

import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/createUserDto';
import { AuthDto } from './dto/auth.dto';
import { TokenGuard } from './guards/token.guard';
import { AuthCookieService } from './lib/authCookie.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private authCookieService: AuthCookieService,
  ) {}

  @Post('register')
  async register(@Req() req: Request, @Body() createUserDto: CreateUserDto) {
    const tokens = await this.authService.register(createUserDto);

    this.authCookieService.setTokensToCookies(req.res, tokens);

    return {
      msg: 'User registered',
    };
  }

  @Post('login')
  async login(@Req() req: Request, @Body() data: AuthDto) {
    const tokens = await this.authService.login(data);

    this.authCookieService.setTokensToCookies(req.res, tokens);

    return {
      msg: 'User logged in',
    };
  }

  @UseGuards(TokenGuard)
  @Get('logout')
  async logout(@Req() req: Request) {
    this.authCookieService.removeTokensFromCookies(req.res);

    await this.authService.logout(req.user['sub']);

    return {
      msg: 'User logged out',
    };
  }
}
