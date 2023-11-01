import env from '@/configs/env'
import { UserService } from '@/modules/user/user.service'
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
/**
 * class JwtStrategy is a strategy for jwt passport
 * @class JwtStrategy
 * @extends PassportStrategy(Strategy)
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: env.JWT_SECRET
    })
  }

  /**
   * validate login as token
   * with jwtStrategy
   * @param payload User
   * @returns Promise User
   */
  async validate(payload: any): Promise<any> {
    return {
      username: payload.username,
      id: payload.sub
    }
  }
}
