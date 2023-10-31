import { PassportStrategy } from '@nestjs/passport'
import { Strategy } from 'passport-local'
import { AuthService } from '../auth.service'
import { Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common'
import { User } from '@prisma/client'
/**
 * class localstrategy
 * @class LocalStrategy
 * @extends PassportStrategy
 */
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super()
  }
  /**
   * validate localStrategy
   * @param email
   * @param password
   * @returns Promise User
   */
  async validate(username: string, password: string): Promise<any> {
    const user = await this.authService.loginLocal({ username: username, password })
    return user
  }
}
