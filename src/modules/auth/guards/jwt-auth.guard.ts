import { AuthGuard } from '@nestjs/passport'
import { Injectable, ExecutionContext, UnauthorizedException, InternalServerErrorException } from '@nestjs/common'
import { Request } from 'express'
import { JwtService } from '@nestjs/jwt'
import { UserService } from '@/modules/user/user.service'
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
    private readonly jwtService: JwtService
  ) {
    super()
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      // extract request
      const request = context.switchToHttp().getRequest<Request>()
      // extract token from header
      const token = this.extractToken(request)
      // verify jwt
      const payload = await this.jwtService.verify(token)
      // validate token
      const user = await this.userService.findUnique({
        username: payload.username,
        id: payload.sub,
        access_token: token
      })
      // check validate token is null or not
      if (user === null) throw new UnauthorizedException('Token is not valid')
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
  /**
   * exract token from header
   * @param request
   * @returns string
   */
  protected extractToken(request: Request): string {
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}