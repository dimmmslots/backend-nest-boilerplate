import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { Response } from 'express'

@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaException implements ExceptionFilter {
  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    let statusCode: number
    let message: string
    let errorResponse: any

    switch (exception.code) {
      case 'P2002':
        statusCode = 409
        message = `${exception.meta.target[0]} already exists`
        errorResponse = { statusCode, message }
        break
      case 'P2025':
        statusCode = 404
        message = 'Resource not found'
        errorResponse = { statusCode, message }
        break
      case 'P2003':
        statusCode = 404
        message = 'Resource not found'
        errorResponse = { statusCode, message, fields: exception.meta }
        break
      default:
        statusCode = 500
        message = 'Internal server error'
        errorResponse = {
          message,
          warning: 'if you see this error, add new if else statement in the prisma exception file',
          obj: exception
        }
    }

    return response.status(statusCode).json(errorResponse)
  }
}
