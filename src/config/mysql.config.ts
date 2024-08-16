import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import * as dotenv from 'dotenv';
import { User } from 'src/user/user.sql.entity';
dotenv.config();

export const mysqlConfig: TypeOrmModuleOptions = {
    type: 'mysql',
    host: '127.0. 0.1',
    port: 3306,
    username: process.env.MYSQL_USERNAME,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    entities: [User],
    synchronize: true,
};

export default null;
