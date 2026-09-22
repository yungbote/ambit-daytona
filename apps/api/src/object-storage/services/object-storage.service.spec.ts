/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createServer, Server, IncomingHttpHeaders } from 'node:http'
import { AddressInfo } from 'node:net'
import * as aws4 from 'aws4'
import { STSClient } from '@aws-sdk/client-sts'
import { TypedConfigService } from '../../config/typed-config.service'
import { ObjectStorageService } from './object-storage.service'

describe('ObjectStorageService endpoint boundaries', () => {
  let server: Server
  let stsEndpoint: string
  let received: { headers: IncomingHttpHeaders; path: string; body: string }

  const values: Record<string, string> = {
    's3.endpoint': 'http://minio.internal:9000',
    's3.publicEndpoint': 'https://storage.example.test',
    's3.defaultBucket': 'workspaces',
    's3.region': 'us-east-1',
    's3.accessKey': 'fixture-access',
    's3.secretKey': 'fixture-secret',
    's3.accountId': '123456789012',
    's3.roleName': 'workspace-upload',
  }

  function service(overrides: Record<string, string | undefined> = {}) {
    const config = { ...values, 's3.stsEndpoint': stsEndpoint, ...overrides }
    return new ObjectStorageService({
      get: (key: string) => config[key],
      getOrThrow: (key: string) => {
        if (config[key] === undefined) throw new Error(`Missing configuration: ${key}`)
        return config[key]
      },
    } as unknown as TypedConfigService)
  }

  beforeEach(async () => {
    server = createServer((request, response) => {
      let body = ''
      request.setEncoding('utf8')
      request.on('data', (chunk) => {
        body += chunk
      })
      request.on('end', () => {
        received = { headers: request.headers, path: request.url!, body }
        response.setHeader('Content-Type', 'application/xml')
        response.end(
          '<AssumeRoleResponse><AssumeRoleResult><Credentials>' +
            '<AccessKeyId>scoped-access</AccessKeyId><SecretAccessKey>scoped-secret</SecretAccessKey>' +
            '<SessionToken>scoped-session</SessionToken>' +
            '</Credentials></AssumeRoleResult></AssumeRoleResponse>',
        )
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    stsEndpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/minio/v1/assume-role?route=sts`
  })

  afterEach(async () => {
    jest.restoreAllMocks()
    server.closeAllConnections()
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  })

  it('uses internal MinIO STS while giving external callers the public storage endpoint', async () => {
    const access = await service().getPushAccess('organization-123')
    expect(access).toEqual({
      accessKey: 'scoped-access',
      secret: 'scoped-secret',
      sessionToken: 'scoped-session',
      organizationId: 'organization-123',
      bucket: 'workspaces',
      storageUrl: 'https://storage.example.test',
    })
    const body = new URLSearchParams(received.body)
    expect(body.get('Action')).toBe('AssumeRole')
    const policy = JSON.parse(body.get('Policy')!)
    expect(policy.Statement[0].Resource).toEqual(['arn:aws:s3:::workspaces/organization-123/*'])
    expect(policy.Statement[1].Condition.StringLike['s3:prefix']).toEqual(['organization-123', 'organization-123/*'])
  })

  it('signs the actual nonstandard STS port, path, query, and configured region', async () => {
    await service({ 's3.region': 'eu-central-1' }).getPushAccess('organization-123')
    const url = new URL(stsEndpoint)
    expect(received.headers.host).toBe(url.host)
    expect(received.path).toBe(url.pathname + url.search)
    const expected = aws4.sign(
      {
        host: url.host,
        path: received.path,
        service: 'sts',
        region: 'eu-central-1',
        method: 'POST',
        body: received.body,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Amz-Date': received.headers['x-amz-date'] as string,
        },
      },
      { accessKeyId: values['s3.accessKey'], secretAccessKey: values['s3.secretKey'] },
    )
    expect(received.headers.authorization).toBe(expected.headers!.Authorization)
    expect(received.headers.authorization).toContain('/eu-central-1/sts/aws4_request')
  })

  it('preserves the existing single endpoint contract when no public endpoint is configured', async () => {
    const access = await service({ 's3.publicEndpoint': undefined }).getPushAccess('organization-123')
    expect(access.storageUrl).toBe(values['s3.endpoint'])
  })

  it.each([undefined, 'https://storage.example.test'])(
    'uses the same optional public endpoint contract for AWS STS: %s',
    async (publicEndpoint) => {
      jest.spyOn(STSClient.prototype, 'send').mockImplementationOnce(async () => ({
        Credentials: { AccessKeyId: 'scoped-access', SecretAccessKey: 'scoped-secret', SessionToken: 'scoped-session' },
      }))
      const access = await service({
        's3.endpoint': 'https://s3.us-east-1.amazonaws.com',
        's3.publicEndpoint': publicEndpoint,
      }).getPushAccess('organization-123')
      expect(access.storageUrl).toBe(publicEndpoint ?? 'https://s3.us-east-1.amazonaws.com')
    },
  )
})
