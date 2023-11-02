import { Injectable } from '@nestjs/common'
import { user } from '@nextui-org/react'
import { PrismaService } from '@prisma/prisma.service'

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async getAllUsers() {
    return await this.prismaService.user.findMany()
  }

  async findUnique({ username, id, access_token }: { username: string; id: string; access_token: string }) {
    return await this.prismaService.user.findUnique({
      where: {
        id,
        username,
        session_token_user: {
          access_token
        }
      },
      include: {
        session_token_user: true
      }
    })
  }
}
