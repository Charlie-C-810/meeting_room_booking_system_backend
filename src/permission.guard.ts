import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class PermissionGuard implements CanActivate {
  @Inject(Reflector)
  private reflector: Reflector;
  /**
   * 判断当前请求用户是否有权限访问特定资源。
   * 此方法用于拦截器中，根据用户权限决定是否继续处理请求。
   *
   * @param context 执行上下文，用于获取当前请求和其他相关信息。
   * @returns 返回布尔值或Promise<boolean>，表示用户是否有权限。
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 从执行上下文中切换到HTTP上下文，并获取当前请求对象
    const request: Request = context.switchToHttp().getRequest();

    // 如果请求对象中没有用户信息，表示无需权限检查，直接通过
    if (!request.user) {
      return true;
    }

    // 获取请求用户的所有权限
    const permissions = request.user.permissions;

    // 通过反射机制获取当前操作所需的权限列表
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      'require-permission',
      [context.getClass(), context.getHandler()],
    );

    // 如果没有设置所需的权限列表，表示无需权限检查，直接通过
    if (!requiredPermissions) {
      return true;
    }
    // 遍历所需权限列表，检查用户是否拥有所有必要的权限
    for (let i = 0; i < requiredPermissions.length; i++) {
      const curPermission = requiredPermissions[i];
      // 在用户的权限列表中查找当前所需权限
      const found = permissions.find((item) => item.code === curPermission);
      // 如果找不到当前所需权限，抛出未授权异常
      if (!found) {
        throw new UnauthorizedException('您没有访问该接口的权限');
      }
    }

    // 如果用户拥有所有所需权限，返回true，表示通过权限检查
    return true;
  }
}
