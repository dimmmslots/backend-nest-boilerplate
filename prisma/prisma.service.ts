import { Injectable, OnModuleInit } from '@nestjs/common'
import { PrismaClient } from '@prisma/client'

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  /**
   * module init and then call prisma connect
   * @function OnModuleInit
   */
  async onModuleInit() {
    await this.$connect()
  }
}
