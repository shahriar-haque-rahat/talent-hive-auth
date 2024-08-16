import { IsNotEmpty } from "class-validator";

export class UserVerifyDto {
    @IsNotEmpty({
        message: 'Token not found'
    })
    readonly token: string;
}