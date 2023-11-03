import { JwtModule, JwtService } from '@nestjs/jwt'
import { Test, type TestingModule } from '@nestjs/testing'
import { JwtUtilService } from './jwt.utils'
import { Request } from 'express'

describe('jwt util test', () => {
  let jwtUtilService: JwtUtilService
  const mockRequest = {
    headers: {
      authorization:
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbG9md2ZqdWgwMDAwdXI4NGw2eWl0Ynh5IiwidXNlcm5hbWUiOiJkaW1hc2FkaSIsImlhdCI6MTY5OTAxNDUxNywiZXhwIjoxNjk5MDE0NTY3fQ.T4BrQUyL_ighBZUijEbdDEWKcAZ0C_SMpb9sLFKb45c'
    }
  } as Request
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [JwtModule],
      providers: [JwtUtilService]
    }).compile()
    jwtUtilService = module.get<JwtUtilService>(JwtUtilService)
  })

  describe('extract token', () => {
    it('should return token', () => {
      expect(jwtUtilService.extractToken(mockRequest)).toEqual(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbG9md2ZqdWgwMDAwdXI4NGw2eWl0Ynh5IiwidXNlcm5hbWUiOiJkaW1hc2FkaSIsImlhdCI6MTY5OTAxNDUxNywiZXhwIjoxNjk5MDE0NTY3fQ.T4BrQUyL_ighBZUijEbdDEWKcAZ0C_SMpb9sLFKb45c'
      )
    })
  })
})
