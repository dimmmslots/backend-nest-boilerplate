import { User } from '@prisma/client'

export interface JwtResponse extends ResponseToken {
  user: User
}

export interface ResponseToken {
  access_token: string
  refresh_token: string
  user?: Omit<User, 'password'>
}

export interface PayloadAccessToken {
  sub: string
  username: string
}
