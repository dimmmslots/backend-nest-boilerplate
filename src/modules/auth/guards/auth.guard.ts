import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common'
/**
 * authenticated user login
 * make as guard service
 * @class AuthenticatedGuard
 * @implements CanActivate
 */
@Injectable()
export class AuthenticatedGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    return request.isAuthenticated()
  }
}
