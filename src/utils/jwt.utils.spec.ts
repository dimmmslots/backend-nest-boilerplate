import { JwtModule, JwtService } from '@nestjs/jwt'
import { Test, type TestingModule } from '@nestjs/testing'
import { JwtUtilService } from './jwt.utils'
import { Request } from 'express'
import { PayloadToken } from '@/types/jwt'
import * as dotenv from 'dotenv'
dotenv.config({ path: '.env' })

describe('jwt util test', () => {
  let jwtUtilService: JwtUtilService
  const mockRequest = {
    headers: {
      authorization:
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbG9md2ZqdWgwMDAwdXI4NGw2eWl0Ynh5IiwidXNlcm5hbWUiOiJkaW1hc2FkaSIsImlhdCI6MTY5OTAxNDUxNywiZXhwIjoxNjk5MDE0NTY3fQ.T4BrQUyL_ighBZUijEbdDEWKcAZ0C_SMpb9sLFKb45c'
    }
  } as Request
  const tokenPayload: PayloadToken = { sub: '123', username: 'user1' }
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

    it('should return undefined because of empty authorization header', () => {
      const customMockRequest = mockRequest
      delete customMockRequest.headers.authorization
      expect(jwtUtilService.extractToken(customMockRequest)).toEqual(undefined)
    })

    it('should return undefined because not using Bearer keyword', () => {
      const customMockRequest = mockRequest
      customMockRequest.headers.authorization =
        'ASD eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbG9md2ZqdWgwMDAwdXI4NGw2eWl0Ynh5IiwidXNlcm5hbWUiOiJkaW1hc2FkaSIsImlhdCI6MTY5OTAxNDUxNywiZXhwIjoxNjk5MDE0NTY3fQ.T4BrQUyL_ighBZUijEbdDEWKcAZ0C_SMpb9sLFKb45c'
      expect(jwtUtilService.extractToken(customMockRequest)).toEqual(undefined)
    })
  })

  describe('generate access token', () => {
    it('should generate access token', async () => {
      await jwtUtilService.generateAccessToken(tokenPayload).then((result) => {
        expect(result).toBeDefined()
        expect(typeof result).toBe('string')
      })
    })
  })

  describe('generate refresh token', () => {
    it('should generate refresh token', async () => {
      await jwtUtilService.generateRefreshToken(tokenPayload).then((result) => {
        expect(result).toBeDefined()
        expect(typeof result).toBe('string')
      })
    })
  })
})
