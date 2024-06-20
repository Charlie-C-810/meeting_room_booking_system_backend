import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { Observable, tap } from 'rxjs';

@Injectable()
export class InvokeRecordInterceptor implements NestInterceptor {
  private readonly logger = new Logger(InvokeRecordInterceptor.name);
  /**
   * 中间件拦截器，用于日志记录。
   * 在请求处理链中，它在请求进入和响应离开时记录相关日志信息。
   *
   * @param context 执行上下文，提供访问请求和响应对象的能力。
   * @param next 接下来的操作处理程序，调用以继续请求处理链。
   * @returns 返回一个Observable，该Observable在处理完请求并生成响应后触发日志记录操作。
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 切换到HTTP上下文并获取请求对象
    const request = context.switchToHttp().getRequest<Request>();
    // 切换到HTTP上下文并获取响应对象
    const response = context.switchToHttp().getResponse<Response>();

    // 获取请求的User-Agent头信息
    const userAgent = request.headers['user-agent'];

    // 解构请求对象中的IP、方法和路径信息
    const { ip, method, path } = request;

    // 记录请求开始时的日志，包括方法、路径、IP、User-Agent以及当前执行的类和方法名称
    this.logger.debug(
      `${method} ${path} ${ip} ${userAgent}: ${context.getClass().name} ${
        context.getHandler().name
      } invoked...`,
    );

    // 如果请求中包含用户信息，记录用户的ID和用户名
    this.logger.debug(
      `user: ${request.user?.userId}, ${request.user?.username}`,
    );

    // 记录当前时间，用于计算请求处理时间
    const now = Date.now();

    // 继续处理请求，并在响应返回时记录处理时间和状态码
    return next.handle().pipe(
      tap((res) => {
        // 计算请求处理时间并记录
        this.logger.debug(
          `${method} ${path} ${ip} ${userAgent}: ${response.statusCode}: ${Date.now() - now}ms`,
        );
        // 记录响应内容
        this.logger.debug(`Response: ${JSON.stringify(res)}`);
      }),
    );
  }
}
