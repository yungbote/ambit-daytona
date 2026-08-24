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
import { SandboxGenerationStopController } from './sandbox-generation-stop.controller'

describe('[AUTH] SandboxGenerationStopController', () => {
  const trackMethod = createCoverageTracker(SandboxGenerationStopController)

  for (const method of ['observeCurrent', 'stopOnce', 'observeStop'] as const) {
    it(method, () => {
      const methodName = trackMethod(method)
      expect(isPublicEndpoint(SandboxGenerationStopController, methodName)).toBe(false)
      expectArrayMatch(getAllowedAuthStrategies(SandboxGenerationStopController, methodName), [
        AuthStrategyType.API_KEY,
        AuthStrategyType.JWT,
      ])
      expectArrayMatch(getAuthContextGuards(SandboxGenerationStopController, methodName), [
        OrganizationAuthContextGuard,
      ])
      expectArrayMatch(getResourceAccessGuards(SandboxGenerationStopController, methodName), [SandboxAccessGuard])
      expectArrayMatch(getRequiredOrganizationResourcePermissions(SandboxGenerationStopController, methodName), [
        OrganizationResourcePermission.WRITE_SANDBOXES,
      ])
    })
  }
})
