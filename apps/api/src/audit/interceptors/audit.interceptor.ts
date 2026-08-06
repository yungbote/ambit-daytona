/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
  InternalServerErrorException,
  HttpException,
  HttpStatus,
} from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request, Response } from 'express'
import { Observable, Subscriber, firstValueFrom } from 'rxjs'
import { AUDIT_CONTEXT_KEY, AuditContext } from '../decorators/audit.decorator'
import { AuditLog, AuditLogMetadata } from '../entities/audit-log.entity'
import { AuditService } from '../services/audit.service'
import { BaseAuthContext, isBaseAuthContext } from '../../common/interfaces/base-auth-context.interface'
import { isUserAuthContext } from '../../common/interfaces/user-auth-context.interface'
import { isOrganizationAuthContext } from '../../common/interfaces/organization-auth-context.interface'
import { isRunnerCleanupToolAuthContext } from '../../common/interfaces/runner-cleanup-tool-auth-context.interface'
import { getAuthContext } from '../../common/utils/get-auth-context'
import { CustomHeaders } from '../../common/constants/header.constants'
import { truncateErrorMessage } from '../../common/utils/truncate-error-message'

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuditInterceptor.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly auditService: AuditService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>()
    const response = context.switchToHttp().getResponse<Response>()

    // TODO: Re-enable after db cleaning
    const auditContext = this.reflector.get<AuditContext>(AUDIT_CONTEXT_KEY, context.getHandler())

    // Non-audited request
    if (!auditContext) {
      return next.handle()
    }

    const authContext = getAuthContext(context, isBaseAuthContext)

    // Dagelic
    if (isUserAuthContext(authContext) && authContext.organizationId === '19336c5f-4f0c-4431-89b0-f42311305913') {
      return next.handle()
    }

    return new Observable((observer) => {
      this.handleAuditedRequest(auditContext, authContext, request, response, next, observer)
    })
  }

  // An audit log must be created before the request is passed to the request handler
  // After the request handler returns, the audit log is optimistically updated with the outcome
  private async handleAuditedRequest(
    auditContext: AuditContext,
    authContext: BaseAuthContext,
    request: Request,
    response: Response,
    next: CallHandler,
    observer: Subscriber<any>,
  ): Promise<void> {
    try {
      const actorId = isUserAuthContext(authContext)
        ? authContext.userId
        : isRunnerCleanupToolAuthContext(authContext)
          ? 'system'
          : authContext.role
      const actorEmail = isUserAuthContext(authContext) ? authContext.email : undefined
      const actorApiKeyPrefix = isUserAuthContext(authContext) ? authContext.apiKey?.keyPrefix : undefined
      const actorApiKeySuffix = isUserAuthContext(authContext) ? authContext.apiKey?.keySuffix : undefined
      const organizationId = isOrganizationAuthContext(authContext) ? authContext.organizationId : undefined

      const auditLog = await this.auditService.createLog({
        actorId,
        actorEmail,
        actorApiKeyPrefix,
        actorApiKeySuffix,
        organizationId,
        action: auditContext.action,
        targetType: auditContext.targetType,
        targetId: this.resolveTargetId(auditContext, request),
        ipAddress: request.ip,
        userAgent: request.get('user-agent'),
        source: request.get(CustomHeaders.SOURCE.name),
        metadata: this.resolveRequestMetadata(auditContext, request),
      })

      try {
        const result = await firstValueFrom(next.handle())

        const resolvedOrganizationId = this.resolveOrganizationId(organizationId, result)
        const resolvedTargetId = this.resolveTargetId(auditContext, request, result)
        const resultMetadata = this.resolveResultMetadata(auditContext, result)
        const metadata = resultMetadata ? { ...(auditLog.metadata ?? {}), ...resultMetadata } : undefined
        const statusCode = response.statusCode || HttpStatus.NO_CONTENT
        await this.recordHandlerSuccess(auditLog, resolvedOrganizationId, resolvedTargetId, statusCode, metadata)

        observer.next(result)
        observer.complete()
      } catch (handlerError) {
        const errorMessage =
          handlerError instanceof HttpException
            ? truncateErrorMessage(handlerError.message)
            : 'An unexpected error occurred.'
        const statusCode = this.resolveErrorStatusCode(handlerError)
        await this.recordHandlerError(auditLog, errorMessage, statusCode)

        observer.error(handlerError)
      }
    } catch (createLogError) {
      this.logger.error('Failed to create audit log:', createLogError)
      observer.error(new InternalServerErrorException())
    }
  }

  private resolveOrganizationId(organizationId: string | undefined, result?: any): string | null {
    return result?.organizationId || organizationId || null
  }

  /**
   * Resolves the identifier of the target resource from the initial request or the response object.
   *
   * Prioritizes resolving the ID from the response object as the request may not include a unique resource identifier (e.g. delete sandbox by name).
   */
  private resolveTargetId(auditContext: AuditContext, request: Request, result?: any): string | null {
    if (auditContext.targetIdFromResult && result) {
      const targetId = auditContext.targetIdFromResult(result)
      if (targetId) {
        return targetId
      }
    }

    if (auditContext.targetIdFromRequest) {
      const targetId = auditContext.targetIdFromRequest(request)
      if (targetId) {
        return targetId
      }
    }

    return null
  }

  private resolveRequestMetadata(auditContext: AuditContext, request: Request): AuditLogMetadata | null {
    return this.resolveMetadata(auditContext.requestMetadata, request, 'request')
  }

  private resolveResultMetadata(auditContext: AuditContext, result: any): AuditLogMetadata | null {
    return this.resolveMetadata(auditContext.resultMetadata, result, 'result')
  }

  private resolveMetadata<T>(
    resolvers: Record<string, (source: T) => any> | undefined,
    source: T,
    sourceName: 'request' | 'result',
  ): AuditLogMetadata | null {
    if (!resolvers) {
      return null
    }

    const resolvedMetadata: AuditLogMetadata = {}

    for (const [key, resolver] of Object.entries(resolvers)) {
      try {
        resolvedMetadata[key] = resolver(source)
      } catch (error) {
        this.logger.warn(`Failed to resolve audit log ${sourceName} metadata key "${key}":`, error)
        resolvedMetadata[key] = null
      }
    }

    return Object.keys(resolvedMetadata).length > 0 ? resolvedMetadata : null
  }

  private async recordHandlerSuccess(
    auditLog: AuditLog,
    organizationId: string | null,
    targetId: string | null,
    statusCode: number,
    metadata?: AuditLogMetadata,
  ): Promise<void> {
    try {
      await this.auditService.updateLog(auditLog.id, {
        organizationId,
        targetId,
        statusCode,
        metadata,
      })
    } catch (error) {
      this.logger.error('Failed to record handler result:', error)
    }
  }

  private async recordHandlerError(auditLog: AuditLog, errorMessage: string, statusCode: number): Promise<void> {
    try {
      await this.auditService.updateLog(auditLog.id, {
        errorMessage,
        statusCode,
      })
    } catch (error) {
      this.logger.error('Failed to record handler error:', error)
    }
  }

  private resolveErrorStatusCode(error: any): number {
    if (error instanceof HttpException) {
      return error.getStatus()
    }

    return HttpStatus.INTERNAL_SERVER_ERROR
  }
}
