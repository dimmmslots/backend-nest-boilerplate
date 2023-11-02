import { Request } from 'express'
/**
 * exract token from header
 * @param request
 * @returns string
 */
export function extractToken(request: Request): string | undefined {
  const authorizationHeader = request.headers.authorization
  if (!authorizationHeader) return undefined
  const [type, token] = authorizationHeader.split(' ') ?? []
  return type === 'Bearer' ? token : undefined
}
