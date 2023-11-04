import { UserService } from '@/modules/user/user.service'
import { JwtUtilService } from '@/utils/jwt.utils'
// import { extractToken } from '@/utils/jwt.utils'

import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { AuthGuard } from '@nestjs/passport'
import { Request } from 'express'
/**
 * JwtAuthGuard Authenctication
 * make as guard
 * @class JwtAuthGuard
 * @extends AuthGuard
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private readonly userService: UserService,
    private readonly jwtUtilService: JwtUtilService,
    private readonly jwtService: JwtService
  ) {
    super()
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      // extract request
      const request = context.switchToHttp().getRequest<Request>()
      // extract token from header
      const token = this.jwtUtilService.extractToken(request)
      // verify jwt
      const payload = await this.jwtService.verify(token)
      // validate token
      const userSession = await this.userService.findUserSession(payload.sub, token)
      // check validate token is null or not
      if (userSession === null) throw new UnauthorizedException('Token is not registered')
      // call super guard
      return (await super.canActivate(context)) as boolean
    } catch (e) {
      throw new UnauthorizedException(e.message)
    }
  }

  handleRequest(err, user) {
    if (err || !user) {
      throw err || new UnauthorizedException()
    }
    return user
  }
}
