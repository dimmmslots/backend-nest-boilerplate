import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Response } from 'express'
import { Observable, map } from 'rxjs'
import { MappingResponse } from '@/common/types/response.type'

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  async intercept(context: ExecutionContext, next: CallHandler<any>): Promise<Observable<MappingResponse>> {
    const response = context.switchToHttp().getResponse<Response>()
    const reflector = new Reflector()
    return next.handle().pipe(
      map((data) => {
        return {
          statusCode: response.statusCode,
          data
        }
      })
    )
  }
}
