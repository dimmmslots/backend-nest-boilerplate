import { AuthGuard } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import env from '@/configs/env'
import { User } from '@prisma/client'
import { AuthService } from '../auth.service'
/**
 * class JwtStrategy is a strategy for jwt passport
 * @class JwtStrategy
 * @extends AuthGuard
 */
export class JwtStrategy extends AuthGuard('jwt') {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: env.JWT_SECRET
    })
  }

  /**
   * validate login as token
   * with jwtStrategy
   * @param payload {username:string,password:string}
   * @returns Promise User
   */
  async validate(payload: { username: string; password: string }): Promise<User> {
    return await this.authService.loginJwt({
      username: payload.username,
      password: payload.password
    })
  }
}
