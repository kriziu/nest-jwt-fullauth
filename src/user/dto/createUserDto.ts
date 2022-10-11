import { IsNotEmpty, IsEmail } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  readonly name: string;

  @IsEmail()
  readonly email: string;

  @IsNotEmpty()
  readonly password: string;

  readonly refreshToken: string;
}

export class UpdateUserDto {
  readonly name: string;

  readonly email: string;

  readonly password: string;

  readonly refreshToken: string;
}
