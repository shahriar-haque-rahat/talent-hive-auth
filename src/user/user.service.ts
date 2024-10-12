import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { User } from './user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as natural from 'natural';

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
    ) { }

    async findAllUser(id: string, limit: number, page: number) {
        try {
            const skip = page * limit;

            const currentUser = await this.userModel.findById(id).select('designation').exec();

            if (!currentUser) {
                throw new NotFoundException('Logged-in user not found');
            }

            const designation = currentUser.designation;

            const users = await this.userModel
                .find({ _id: { $ne: id } })
                .select('-password -__V')
                .skip(skip)
                .limit(limit)
                .exec();

            let usersWithSimilarity = users.map(user => {
                if (!user.designation) {
                    return { user, similarity: 0 };
                }

                const similarity = natural.JaroWinklerDistance(user.designation, designation);
                return { user, similarity };
            });

            let filteredUsers = usersWithSimilarity.filter(item => item.similarity > 0.7);

            if (filteredUsers.length < limit) {
                usersWithSimilarity.sort((a, b) => b.similarity - a.similarity);

                filteredUsers = usersWithSimilarity.slice(0, limit);
            } else {
                filteredUsers = filteredUsers.slice(0, limit);
            }

            const result = filteredUsers.map(item => item.user);

            if (result.length === 0) {
                throw new NotFoundException('No users found with similar designations');
            }

            const payload = {
                users: result,
                page: +page + 1,
            }

            return payload;
        }
        catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Unable to get users'
            );
        }
    }

    async findUserById(id: string) {
        try {
            const user = await this.userModel.findById(id).select('-password -__v').exec();

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

    async updateUser(id: string, updateData: Partial<User>) {
        try {
            const updatedUser = await this.userModel.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).exec();

            if (!updatedUser) {
                throw new NotFoundException('User not found');
            }

            return updatedUser;
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Unable to update the user'
            );
        }
    }

    async deleteUser(id: string) {
        try {
            const deletedUser = await this.userModel.findByIdAndDelete(id).exec();

            if (!deletedUser) {
                throw new NotFoundException('User not found');
            }

            return { message: 'User successfully deleted' };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Unable to delete the user'
            );
        }
    }
}
