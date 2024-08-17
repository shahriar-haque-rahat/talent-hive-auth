import { IsNotEmpty } from 'class-validator';

export class UserRefreshDto {
  @IsNotEmpty()
  readonly refreshToken: string;
}
