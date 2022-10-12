import { Controller, Get, Post, Body, UseGuards, Req } from '@nestjs/common';

import { Request } from 'express';

import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/createUserDto';
import { AuthDto } from './dto/auth.dto';
import { AccessTokenGuard } from './guards/accessToken.guard';
import { RefreshTokenGuard } from './guards/refreshToken.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Req() req: Request, @Body() createUserDto: CreateUserDto) {
    return await this.authService.register(createUserDto);
  }

  @Post('login')
  async login(@Req() req: Request, @Body() data: AuthDto) {
    return await this.authService.login(data);
  }

  @UseGuards(AccessTokenGuard)
  @Get('logout')
  async logout(@Req() req: Request) {
    await this.authService.logout(req.user['sub']);

    return {
      msg: 'User logged out',
    };
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refresh(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];

    return this.authService.refreshTokens(userId, refreshToken);
  }
}
