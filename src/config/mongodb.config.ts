import { MongooseModuleOptions } from '@nestjs/mongoose';
import * as dotenv from 'dotenv';

dotenv.config();

export const mongoConfig: MongooseModuleOptions = {
    uri: process.env.MONGO_URI,
};

export default mongoConfig;
