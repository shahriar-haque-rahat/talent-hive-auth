import { Controller, Get, Param } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get('all-user')
    findAllUser() {
        return this.userService.findAllUser();
    }

    @Get(':uid')
    findUserById(@Param('uid') uid: string) {
        return this.userService.findUserById(uid);
    }
}
