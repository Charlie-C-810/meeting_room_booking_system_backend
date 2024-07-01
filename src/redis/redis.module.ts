import { Global, Module } from '@nestjs/common';
import { RedisService } from './redis.service';
import { createClient } from 'redis';
import { ConfigService } from '@nestjs/config';

// 声明为全局模块
@Global()
@Module({
  exports: [RedisService],
  providers: [
    RedisService,
    {
      provide: 'REDIS_CLIENT',
      /**
       * 创建并连接到Redis客户端的异步工厂函数。
       *
       * 本函数旨在初始化一个Redis客户端实例，并确保通过调用connect方法建立与Redis服务器的连接。
       * 使用createClient函数配置客户端，指定Redis服务器的主机、端口和数据库编号。
       *
       * @returns {Promise<RedisClient>} 返回一个Promise，解析为已连接的Redis客户端实例。
       */
      async useFactory(configService: ConfigService) {
        console.log(
          'configService.get(redis_server_host)',
          configService.get('redis_server_host'),
        );
        // 创建Redis客户端实例，配置包括主机、端口和数据库号。
        const client = createClient({
          socket: {
            host: configService.get('redis_server_host'),
            port: configService.get('redis_server_port'),
          },
          database: configService.get('redis_server_db'),
        });
        // 等待客户端连接到Redis服务器。
        await client.connect();
        // 返回已连接的Redis客户端实例。
        return client;
      },
      inject: [ConfigService],
    },
  ],
})
export class RedisModule {}
