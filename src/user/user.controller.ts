import { Body, Controller, Delete, Get, Param, Patch, Query } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './user.schema';

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

    @Get('suggestion-user/:id')
    async getSuggestions(@Param('id') id: string) {
        return this.userService.findSuggestionUser(id);
    }

    @Get(':id')
    findUserById(@Param('id') id: string) {
        return this.userService.findUserById(id);
    }

    @Patch(':id')
    updateUser(
        @Param('id') id: string,
        @Body() updateData: Partial<User>
    ) {
        return this.userService.updateUser(id, updateData);
    }

    @Delete(':id')
    deleteUser(@Param('id') id: string) {
        return this.userService.deleteUser(id);
    }
}
