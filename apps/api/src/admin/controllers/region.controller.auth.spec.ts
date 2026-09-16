/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { AdminRegionController } from './region.controller'
import { AuthStrategyType } from '../../auth/enums/auth-strategy-type.enum'
import { SystemRole } from '../../user/enums/system-role.enum'
import { AUDIT_CONTEXT_KEY, AuditContext } from '../../audit/decorators/audit.decorator'
import { AuditAction } from '../../audit/enums/audit-action.enum'
import { AuditTarget } from '../../audit/enums/audit-target.enum'
import {
  getAllowedAuthStrategies,
  getRequiredSystemRole,
  isPublicEndpoint,
} from '../../test/helpers/controller-metadata.helper'

describe('[AUTH] AdminRegionController', () => {
  it.each(['create', 'findOne'] as const)('%s retains system-admin authentication', (method) => {
    expect(getRequiredSystemRole(AdminRegionController, method)).toBe(SystemRole.ADMIN)
    expect(isPublicEndpoint(AdminRegionController, method)).toBe(false)
    expect(getAllowedAuthStrategies(AdminRegionController, method)).toEqual([
      AuthStrategyType.API_KEY,
      AuthStrategyType.JWT,
    ])
  })

  it('audits the actual created identity and reviewed name without copying extra request fields', () => {
    const context = Reflect.getMetadata(AUDIT_CONTEXT_KEY, AdminRegionController.prototype.create) as AuditContext
    expect(context.action).toBe(AuditAction.CREATE)
    expect(context.targetType).toBe(AuditTarget.REGION)
    expect(context.targetIdFromResult({ id: 'created-region' })).toBe('created-region')
    expect(
      context.requestMetadata.body({ body: { name: 'qualified', id: 'forged', secret: 'not-audit-data' } } as never),
    ).toEqual({
      name: 'qualified',
    })
  })
})
