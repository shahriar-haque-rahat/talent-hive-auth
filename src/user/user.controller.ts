import { Controller, Get, Param } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get('all-user')
    findAllUser() {
        return this.userService.findAllUser();
    }

    @Get(':id')
    findUserById(@Param('id') id: string) {
        return this.userService.findUserById(id);
    }

    @Get('uid/:uid')
    findUserByUid(@Param('uid') uid: string) {
        return this.userService.findUserByUid(uid);
    }
}
