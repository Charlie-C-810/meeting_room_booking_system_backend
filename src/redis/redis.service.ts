import { Inject, Injectable } from '@nestjs/common';
import { RedisClientType } from 'redis';

@Injectable()
export class RedisService {
  @Inject('REDIS_CLIENT') private readonly redisClient: RedisClientType;

  /**
   * 异步获取指定键的值。
   *
   * 该方法通过异步方式从Redis客户端获取指定键对应的值。这允许我们在不阻塞主线程的情况下，
   * 等待Redis服务器的响应。使用异步编程模式可以提高应用程序的响应能力和吞吐量。
   *
   * @param key 需要获取值的键，作为Redis中的键来检索数据。
   * @returns 返回一个Promise，解析为从Redis获取的值。如果键不存在，则解析为null。
   */
  async get(key: string) {
    return await this.redisClient.get(key);
  }

  /**
   * 将给定的键值对存储到Redis中，并可选地设置过期时间。
   *
   * 此函数首先将键值对存储到Redis中，然后如果指定了过期时间（ttl），则进一步设置该键的过期时间。
   * 这对于缓存数据或临时存储信息非常有用，可以确保数据在一段时间后自动被清理。
   *
   * @param key 要存储的键，必须是字符串。
   * @param value 要存储的值，可以是字符串或数字。
   * @param ttl 可选参数，指定键的过期时间（以秒为单位）。如果不提供，则键将不会设置过期时间。
   */
  async set(key: string, value: string | number, ttl?: number) {
    await this.redisClient.set(key, value);
    if (ttl) {
      await this.redisClient.expire(key, ttl);
    }
  }
}
