import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.sql.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
    ) { }

    async findUserById(id: number) {
        try {
            const user = await this.userRepository.findOneBy({ id });

            if (!user) {
                throw new NotFoundException('User not found');
            };

            return user;
        }
        catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Unable to get the user'
            );
        }
    }
}
