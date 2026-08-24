/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import axios, { AxiosError, AxiosInstance } from 'axios'
import axiosDebug from 'axios-debug-log'
import axiosRetry from 'axios-retry'
import { Logger } from '@nestjs/common'

import { Runner } from '../entities/runner.entity'
import { RunnerApiError } from '../errors/runner-api-error'

const RETRYABLE_NETWORK_ERROR_CODES = ['ECONNRESET', 'ETIMEDOUT']
const RUNNER_HTTP_TIMEOUT_MS = 15 * 60 * 1000

/**
 * One authenticated runner HTTP transport shared by every direct runner API
 * surface. V2 lifecycle effects remain job-driven; provider custody reads use
 * this same narrow transport because they require a synchronous exact receipt.
 */
export function createRunnerHttpClient(runner: Runner, logger: Logger): AxiosInstance {
  if (!runner.apiUrl) {
    throw new Error(`Runner ${runner.id} has no API URL`)
  }

  const client = axios.create({
    baseURL: runner.apiUrl,
    headers: { Authorization: `Bearer ${runner.apiKey}` },
    timeout: RUNNER_HTTP_TIMEOUT_MS,
  })
  const retryErrorMap = new WeakMap<AxiosError, string>()
  axiosRetry(client, {
    retries: 3,
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: (error) => {
      const matched = RETRYABLE_NETWORK_ERROR_CODES.find(
        (code) =>
          error.code === code ||
          error.message?.includes(code) ||
          (error.cause as { code?: string } | undefined)?.code === code,
      )
      if (matched) retryErrorMap.set(error, matched)
      return matched !== undefined
    },
    onRetry: (retryCount, error, requestConfig) => {
      logger.warn(
        `Retrying runner request due to ${retryErrorMap.get(error)} (attempt ${retryCount}): ${requestConfig.method?.toUpperCase()} ${requestConfig.url}`,
      )
    },
  })
  client.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      const response = error.response
      const data = response?.data as
        | Readonly<{ message?: unknown; statusCode?: unknown; code?: unknown }>
        | string
        | undefined
      const message =
        (typeof data === 'object' && data !== null ? data.message : data) ?? error.message ?? String(error)
      const statusCode =
        (typeof data === 'object' && data !== null ? data.statusCode : undefined) ?? response?.status ?? error.status
      const code =
        (typeof data === 'object' && data !== null ? data.code : undefined) ??
        error.code ??
        (error.cause as { code?: string } | undefined)?.code ??
        ''
      throw new RunnerApiError(String(message), Number(statusCode) || undefined, String(code))
    },
  )
  if (process.env.DEBUG === 'true') axiosDebug.addLogger(client)
  return client
}
