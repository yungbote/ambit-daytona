/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Injectable } from '@nestjs/common'
import axios from 'axios'
import { Readable } from 'node:stream'

import { Runner } from '../entities/runner.entity'
import { RunnerApiError } from '../errors/runner-api-error'

export const SPECIALIST_RENDER_CONTENT_TYPE =
  'application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1' as const

export type RunnerSpecialistRenderStreamResponse = Readonly<{
  status: number
  contentType: string
  body: Readable
}>

@Injectable()
export class RunnerSpecialistRenderTransport {
  async execute(
    runner: Runner,
    sandboxId: string,
    body: Readable,
    signal: AbortSignal,
  ): Promise<RunnerSpecialistRenderStreamResponse> {
    const client = exactClient(runner)
    const response = await client.post(`/sandboxes/${encodeURIComponent(sandboxId)}/specialist-renders`, body, {
      signal,
      responseType: 'stream',
      headers: { 'Content-Type': SPECIALIST_RENDER_CONTENT_TYPE },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      validateStatus: () => true,
    })
    if (!(response.data instanceof Readable)) {
      throw new RunnerApiError('Runner specialist-render response is not a stream.', response.status)
    }
    return Object.freeze({
      status: response.status,
      contentType: String(response.headers['content-type'] ?? ''),
      body: response.data,
    })
  }

  async observeCurrent(runner: Runner, sandboxId: string, request: unknown, signal: AbortSignal): Promise<unknown> {
    return this.json(runner, `/sandboxes/${encodeURIComponent(sandboxId)}/generation/observe-current`, request, signal)
  }

  async observeRender(runner: Runner, sandboxId: string, request: unknown, signal: AbortSignal): Promise<unknown> {
    return this.json(runner, `/sandboxes/${encodeURIComponent(sandboxId)}/specialist-renders/observe`, request, signal)
  }

  private async json(runner: Runner, path: string, request: unknown, signal: AbortSignal): Promise<unknown> {
    const response = await exactClient(runner).post(path, request, {
      signal,
      headers: { 'Content-Type': 'application/json' },
      maxBodyLength: 32 * 1024,
      maxContentLength: 128 * 1024,
      validateStatus: () => true,
    })
    if (response.status < 200 || response.status >= 300) {
      const value = response.data as { message?: unknown; code?: unknown } | string | undefined
      throw new RunnerApiError(
        String(typeof value === 'object' && value !== null ? (value.message ?? 'Runner request failed.') : value),
        response.status,
        String(typeof value === 'object' && value !== null ? (value.code ?? '') : ''),
      )
    }
    return response.data
  }
}

function exactClient(runner: Runner) {
  if (!runner.apiUrl) throw new Error(`Runner ${runner.id} has no API URL`)
  return axios.create({
    baseURL: runner.apiUrl,
    headers: { Authorization: `Bearer ${runner.apiKey}` },
    timeout: 55 * 60 * 1000,
    maxRedirects: 0,
    decompress: false,
    proxy: false,
  })
}
