import {
  ExecutionContext,
  SetMetadata,
  createParamDecorator,
} from '@nestjs/common';

export const RequireLogin = () => SetMetadata('require-login', true);

export const RequirePermission = (...permissions: string[]) =>
  SetMetadata('require-permission', permissions);

/**
 * 创建一个参数装饰器，用于从HTTP请求中提取用户信息。
 *
 * @param data 可选参数，指定需要提取的用户信息的具体属性。
 * @param ctx 执行上下文，用于访问HTTP请求和其他上下文信息。
 * @returns 返回用户信息的特定属性，如果没有指定属性，则返回整个用户信息对象；如果请求中不存在用户信息，则返回null。
 */
export const UserInfo = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    // 切换到HTTP上下文并获取请求对象
    const request = ctx.switchToHttp().getRequest();

    // 检查请求对象中是否存在用户信息
    if (!request.user) {
      return null;
    }

    // 如果指定了数据属性，则返回用户信息的该属性值；否则返回整个用户信息对象
    return data ? request.user[data] : request.user;
  },
);
