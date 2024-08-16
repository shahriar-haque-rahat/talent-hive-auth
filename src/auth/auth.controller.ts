import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserRegisterDto } from './dto/user-register.dto';
import { User } from 'src/user/user.sql.entity';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService){}

    @Post('register')
    register(@Body() userRegisterDto: UserRegisterDto): Promise<User> {
        return this.authService.register(userRegisterDto);
    }
}
