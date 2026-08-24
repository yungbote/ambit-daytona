/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { AuthStrategyType } from '../../auth/enums/auth-strategy-type.enum'
import { OrganizationResourcePermission } from '../../organization/enums/organization-resource-permission.enum'
import { OrganizationAuthContextGuard } from '../../organization/guards/organization-auth-context.guard'
import {
  createCoverageTracker,
  expectArrayMatch,
  getAllowedAuthStrategies,
  getAuthContextGuards,
  getRequiredOrganizationResourcePermissions,
  getResourceAccessGuards,
  isPublicEndpoint,
} from '../../test/helpers/controller-metadata.helper'
import { SandboxAccessGuard } from '../guards/sandbox-access.guard'
import { WorkingCopyCaptureController } from './working-copy-capture.controller'

describe('[AUTH] WorkingCopyCaptureController', () => {
  const trackMethod = createCoverageTracker(WorkingCopyCaptureController)

  for (const method of ['capture', 'observe', 'read', 'delete', 'exists'] as const) {
    it(method, () => {
      const methodName = trackMethod(method)
      expect(isPublicEndpoint(WorkingCopyCaptureController, methodName)).toBe(false)
      expectArrayMatch(getAllowedAuthStrategies(WorkingCopyCaptureController, methodName), [
        AuthStrategyType.API_KEY,
        AuthStrategyType.JWT,
      ])
      expectArrayMatch(getAuthContextGuards(WorkingCopyCaptureController, methodName), [OrganizationAuthContextGuard])
      expectArrayMatch(getResourceAccessGuards(WorkingCopyCaptureController, methodName), [SandboxAccessGuard])
      expectArrayMatch(getRequiredOrganizationResourcePermissions(WorkingCopyCaptureController, methodName), [
        OrganizationResourcePermission.WRITE_SANDBOXES,
      ])
    })
  }
})
