import * as dotenv from 'dotenv';
dotenv.config();
import * as redisStore from 'cache-manager-redis-store';

export const cacheConfig = {
    isGlobal: true,
    useFactory: async () => ({
        store: redisStore,
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
        // ttl: 5000,
    })
};
