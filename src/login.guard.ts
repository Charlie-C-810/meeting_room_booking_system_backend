import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Permission } from './user/entities/permissions.entity';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';

interface JwtUserData {
  userId: number;
  username: string;
  roles: string[];
  permissions: Permission[];
}

// 扩展Express模块的Request接口，以便在请求中包含用户数据
declare module 'express' {
  // 通过添加一个名为"user"的属性，我们可以在Request对象中存储JWT用户数据
  interface Request {
    // JwtUserData是一个接口，它应该定义了JWT用户数据的结构
    user: JwtUserData;
  }
}

@Injectable()
export class LoginGuard implements CanActivate {
  @Inject()
  private reflector: Reflector;

  @Inject(JwtService)
  private jwtService: JwtService;
  /**
   * 判断当前请求是否具有访问权限。
   * 此守卫用于检查请求是否具有有效的登录令牌，以决定是否允许请求继续。
   *
   * @param context 执行上下文，用于获取当前请求的信息。
   * @returns 如果请求具有有效令牌，则返回true；如果不需要登录，则直接返回true；否则抛出未授权异常。
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 从执行上下文中切换到HTTP上下文，并获取当前请求对象
    const request: Request = context.switchToHttp().getRequest();

    // 用 reflector 从目标 controller 和 handler 上拿到 require-login 的 metadata
    const requireLogin = this.reflector.getAllAndOverride('require-login', [
      context.getClass(),
      context.getHandler(),
    ]);

    // 如果当前操作不需要登录，则直接返回true，允许访问
    if (!requireLogin) {
      return true;
    }

    // 检查请求头中是否包含授权信息
    const authorization = request.headers.authorization;
    // 如果没有授权信息，则抛出未授权异常
    if (!authorization) {
      throw new UnauthorizedException('用户未登录');
    }

    try {
      // 从授权信息中提取令牌，并使用JWT服务验证令牌的有效性
      const token = authorization.split(' ')[1];
      const data = this.jwtService.verify<JwtUserData>(token);

      // 将令牌中的用户信息附加到请求对象上，以便后续的中间件或控制器可以使用
      request.user = {
        userId: data.userId,
        username: data.username,
        roles: data.roles,
        permissions: data.permissions,
      };
      return true;
    } catch (error) {
      // 如果令牌验证失败，则抛出未授权异常
      throw new UnauthorizedException('token 失效，请重新登录');
    }
  }
}
