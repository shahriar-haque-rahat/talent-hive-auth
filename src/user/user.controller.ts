import { Controller, Get, Param, Query } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get('all-user/:id')
    findAllUser(
        @Param('id') id: string,
        @Query('limit') limit?: number,
        @Query('page') page?: number
    ) {
        return this.userService.findAllUser(id, limit, page);
    }

    @Get(':id')
    findUserById(@Param('id') id: string) {
        return this.userService.findUserById(id);
    }
}
