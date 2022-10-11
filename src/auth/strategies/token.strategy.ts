import { Injectable, ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PassportStrategy } from '@nestjs/passport';

import { Request } from 'express';
import { Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';

import { AuthCookieService } from '../lib/authCookie.service';

type JwtPayload = {
  sub: string;
  username: string;
  exp: number;
};

const CookieExtractor = (req: Request, cookieName: string) => {
  let token = null;
  if (req && req.cookies && req.cookies[cookieName]) {
    token = req.cookies[cookieName].replace('Bearer ', '').trim();
  }

  return token;
};

@Injectable()
export class TokenStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private authService: AuthService,
    private jwtService: JwtService,
    private authCookieService: AuthCookieService,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: (req: Request) => CookieExtractor(req, 'access-token'),
      ignoreExpiration: true,
      secretOrKey: configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JwtPayload) {
    const refreshToken = CookieExtractor(req, 'refresh-token');

    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) {
      console.log('Access token expired');
      await this.jwtService
        .verifyAsync(refreshToken, {
          secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
        })
        .catch(() => {
          throw new ForbiddenException('Invalid refresh token');
        });

      const tokens = await this.authService.refreshTokens(
        payload.sub,
        refreshToken,
      );

      const newPayload = this.jwtService.decode(
        tokens.accessToken,
      ) as JwtPayload;

      this.authCookieService.setTokensToCookies(req.res, tokens);

      return newPayload;
    }

    return payload;
  }
}
