import { Redis } from 'ioredis';
import { log } from '@/utils/log';

function createRedisClient(): Redis {
    const url = process.env.REDIS_URL;
    if (!url) {
        throw new Error('REDIS_URL environment variable is required when Redis is enabled');
    }

    const client = new Redis(url, {
        maxRetriesPerRequest: 3,
        retryStrategy(times) {
            const delay = Math.min(times * 100, 5000);
            return delay;
        },
    });

    client.on('error', (err) => {
        log({ module: 'redis', level: 'error' }, `Redis connection error: ${err.message}`);
    });

    client.on('connect', () => {
        log({ module: 'redis' }, 'Redis connected');
    });

    return client;
}

export const redis = createRedisClient();
