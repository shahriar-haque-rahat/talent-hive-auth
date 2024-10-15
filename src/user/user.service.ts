import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { User } from './user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as natural from 'natural';
import axios from 'axios';

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
    ) { }

    async findAllUser(id: string, limit: number, page: number) {
        try {
            let result = [];
            let totalFetched = 0;
            let skip = page * limit;

            while (result.length < limit) {
                const users = await this.userModel
                    .find({ _id: { $ne: id } })
                    .select('-password -__v')
                    .skip(skip)
                    .limit(limit)
                    .exec();


                if (users.length === 0) {
                    break;
                }

                const userIds = users.map(user => user._id.toString());

                const response = await axios.post(`${process.env.PUBLIC_SERVER_URL}/connection-request/check-status`, {
                    loggedInUserId: id,
                    userIds,
                });

                const noRelationshipUsers = users.filter(user =>
                    response.data.some(res => res.userId === user._id.toString() && res.status === 'no_relationship')
                );

                result = result.concat(noRelationshipUsers);

                if (result.length >= limit) {
                    break;
                }

                totalFetched += users.length;
                skip = totalFetched;

            }

            const payload = {
                users: result.slice(0, limit),
                page: +page + 1,
            };

            return payload;
        } catch (error) {
            console.error('Error fetching users:', error);
            throw new InternalServerErrorException(error.message || 'Unable to get users');
        }
    }

    async findSuggestionUser(id: string, limit: number = 3) {
        try {
            const currentUser = await this.userModel.findById(id).select('designation').exec();
            if (!currentUser) {
                throw new NotFoundException('Logged-in user not found');
            }

            let suggestedUsers = [];
            const processedUserIds = new Set();
            let skip = 0;

            while (suggestedUsers.length < limit) {
                const users = await this.userModel
                    .find({
                        _id: { $ne: id, $nin: Array.from(processedUserIds) }
                    })
                    .select('-password -__v')
                    .skip(skip)
                    .limit(limit - suggestedUsers.length)
                    .exec();

                if (users.length === 0) {
                    break;
                }

                const userIds = users.map(user => user._id.toString());
                userIds.forEach(userId => processedUserIds.add(userId));

                const response = await axios.post(`${process.env.PUBLIC_SERVER_URL}/connection-request/check-status`, {
                    loggedInUserId: id,
                    userIds
                });

                const noRelationshipUserIds = response.data
                    .filter(user => user.status === 'no_relationship')
                    .map(user => user.userId);

                const usersWithNoRelationship = users.filter(user =>
                    noRelationshipUserIds.includes(user._id.toString())
                );

                suggestedUsers = suggestedUsers.concat(usersWithNoRelationship);
                skip += users.length;

                if (suggestedUsers.length >= limit) {
                    break;
                }
            }

            if (suggestedUsers.length < limit) {
                throw new NotFoundException('Not enough users found with no relationships.');
            }

            return {
                users: suggestedUsers.slice(0, limit),
                page: 1,
            };
        } catch (error) {
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
