import { IsNotEmpty } from 'class-validator';

export class UserResetPasswordDto {
    @IsNotEmpty()
    readonly token: string;

    @IsNotEmpty()
    readonly newPassword: string;
}
