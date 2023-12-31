import { Injectable } from '@nestjs/common'
import { PassportSerializer } from '@nestjs/passport'
@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor() {
    super()
  }
  serializeUser(user: any, done: any) {
    done(null, user)
  }

  deserializeUser(payload: any, done: any) {
    done(null, payload)
  }
}
