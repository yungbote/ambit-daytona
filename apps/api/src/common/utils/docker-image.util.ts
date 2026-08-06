/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

/**
 * Interface representing parsed Docker image information
 */
export interface DockerImageInfo {
  /** The full registry hostname (e.g. 'registry:5000' or 'docker.io') */
  registry?: string
  /** The project/organization name (e.g. 'test' in 'registry:5000/test/image') */
  project?: string
  /** The repository/image name (e.g. 'image' in 'registry:5000/test/image') */
  repository: string
  /** The mutable tag (e.g. 'latest') */
  tag?: string
  /** The immutable content digest (e.g. 'sha256:123...') */
  digest?: string
  /** The full original image name */
  originalName: string
}

export class DockerImage implements DockerImageInfo {
  registry?: string
  project?: string
  repository: string
  tag?: string
  digest?: string
  originalName: string

  constructor(info: DockerImageInfo) {
    this.registry = info.registry
    this.project = info.project
    this.repository = info.repository
    this.tag = info.tag
    this.digest = info.digest
    this.originalName = info.originalName
  }

  getFullName(): string {
    let name = this.repository
    if (this.project) {
      name = `${this.project}/${name}`
    }
    if (this.registry) {
      name = `${this.registry}/${name}`
    }
    if (this.tag) {
      name = `${name}:${this.tag}`
    }
    if (this.digest) {
      name = `${name}@${this.digest}`
    }
    return name
  }
}

/**
 * Parses a Docker image name into its component parts
 *
 * @param imageName - The full image name (e.g. 'registry:5000/test/image:latest')
 * @returns Parsed image information
 *
 * Examples:
 * - registry:5000/test/image:latest -> { registry: 'registry:5000', project: 'test', repository: 'image', tag: 'latest' }
 * - docker.io/library/ubuntu:20.04 -> { registry: 'docker.io', project: 'library', repository: 'ubuntu', tag: '20.04' }
 * - ubuntu:20.04 -> { registry: undefined, project: undefined, repository: 'ubuntu', tag: '20.04' }
 * - ubuntu -> { registry: undefined, project: undefined, repository: 'ubuntu', tag: undefined }
 */
export function parseDockerImage(imageName: string): DockerImage {
  // Handle empty or invalid input
  if (!imageName) {
    throw new Error('Image name cannot be empty')
  }

  const result: DockerImageInfo = {
    originalName: imageName,
    repository: '',
  }

  const digestSeparatorIndex = imageName.indexOf('@')
  if (digestSeparatorIndex !== imageName.lastIndexOf('@')) {
    throw new Error('Invalid image name. At most one digest is allowed')
  }

  let nameWithOptionalTag = imageName
  if (digestSeparatorIndex >= 0) {
    nameWithOptionalTag = imageName.substring(0, digestSeparatorIndex)
    const digest = imageName.substring(digestSeparatorIndex + 1)
    if (!nameWithOptionalTag || !/^sha256:[a-f0-9]{64}$/.test(digest)) {
      throw new Error('Invalid digest format. Must be image@sha256:64_hex_characters')
    }
    result.digest = digest
  }

  const lastSlashIndex = nameWithOptionalTag.lastIndexOf('/')
  const lastColonIndex = nameWithOptionalTag.lastIndexOf(':')
  const hasTag = lastColonIndex > lastSlashIndex
  const nameWithoutTag = hasTag ? nameWithOptionalTag.substring(0, lastColonIndex) : nameWithOptionalTag
  if (hasTag) {
    const tag = nameWithOptionalTag.substring(lastColonIndex + 1)
    if (!tag) {
      throw new Error('Invalid image name. Tag cannot be empty')
    }
    result.tag = tag
  }

  const parts = nameWithoutTag.split('/')
  if (parts.some((part) => part === '')) {
    throw new Error('Invalid image name. A part is empty')
  }

  // Check if first part looks like a registry hostname (contains '.' or ':' or is 'localhost')
  if (parts.length >= 2 && (parts[0].includes('.') || parts[0].includes(':') || parts[0] === 'localhost')) {
    result.registry = parts[0]
    parts.shift() // Remove registry part
  }

  // Handle remaining parts
  if (parts.length >= 2) {
    // Format: [registry/]project/repository
    result.project = parts.slice(0, -1).join('/')
    result.repository = parts[parts.length - 1]
  } else {
    // Format: repository
    result.repository = parts[0]
  }

  return new DockerImage(result)
}

/**
 * Extracts the image reference from every FROM statement in a Dockerfile.
 *
 * Note: aliases referencing earlier build stages (e.g. `FROM builder`) are
 * returned too, so callers should treat the results as candidate image names.
 *
 * @param dockerfileContent - The full Dockerfile content as a string
 * @returns The list of FROM image references in order of appearance
 */
export function extractDockerfileFromImages(dockerfileContent: string): string[] {
  const lines = dockerfileContent.split('\n')

  // Regex to match FROM statements
  const fromRegex = /^\s*FROM\s+(?:--[a-z-]+=[^\s]+\s+)*([^\s]+)(?:\s+AS\s+[^\s]+)?/i

  const images: string[] = []
  for (const line of lines) {
    // Remove inline comments (everything after #)
    const lineWithoutComment = line.split('#')[0]
    const trimmedLine = lineWithoutComment.trim()

    // Skip empty lines and comment-only lines
    if (!trimmedLine) {
      continue
    }

    const match = fromRegex.exec(trimmedLine)
    if (match && match[1]) {
      images.push(match[1].trim())
    }
  }

  return images
}

/**
 * Checks if the Dockerfile content contains any FROM images that may require registry credentials.
 * This includes:
 * - Private registry images (e.g., 'myregistry.com/image', 'registry:5000/image')
 * - Private Docker Hub images (e.g., 'username/my-private-image')
 *
 * @param dockerfileContent - The full Dockerfile content as a string
 * @returns true if any FROM image may require credentials, false otherwise
 *
 * Example:
 * - FROM node:18 -> false (public Docker Hub library image)
 * - FROM username/my-image:0.0.1 -> true (private Docker Hub image)
 * - FROM myregistry.com/myimage:latest -> true (private registry)
 * - FROM registry:5000/test/image -> true (private registry)
 */
export function checkDockerfileHasRegistryPrefix(dockerfileContent: string): boolean {
  // Check if image has a path component (contains '/')
  // This covers both private registries and private Docker Hub images (namespace/image)
  return extractDockerfileFromImages(dockerfileContent).some((imageName) => imageName.includes('/'))
}
