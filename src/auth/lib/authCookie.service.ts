import { Injectable } from '@nestjs/common';
import { Response } from 'express';

@Injectable()
export class AuthCookieService {
  private readonly refreshTokenName = 'refresh-token';
  private readonly accessTokenName = 'access-token';

  setTokensToCookies(
    res: Response,
    tokens: { accessToken: string; refreshToken: string },
  ) {
    res.cookie('access-token', `Bearer ${tokens.accessToken}`, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
    res.cookie('refresh-token', `Bearer ${tokens.refreshToken}`, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
  }

  removeTokensFromCookies(res: Response) {
    res.clearCookie(this.refreshTokenName);
    res.clearCookie(this.accessTokenName);
  }
}
