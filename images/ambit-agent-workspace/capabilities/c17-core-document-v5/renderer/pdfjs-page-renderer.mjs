import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { types as nodeTypes } from 'node:util'

import {
  admitPngPageEvidence,
  admitRenderPolicy,
  planPageDimensions,
} from './render-contracts.mjs'

export const CORE_DOCUMENT_V5_PACK_ROOT =
  '/opt/ambit/runtime-pack/core-document-v5'
export const EXPECTED_PDFJS_VERSION = '6.2.108'
export const EXPECTED_CANVAS_VERSION = '1.0.7'

function ownDataValue(value, key) {
  if (
    value === null ||
    (typeof value !== 'object' && typeof value !== 'function') ||
    nodeTypes.isProxy(value)
  ) {
    return undefined
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key)
  return descriptor && Object.hasOwn(descriptor, 'value')
    ? descriptor.value
    : undefined
}

function exactPackageIdentity(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError('Canvas package identity must be plain data.')
  }
  const name = ownDataValue(value, 'name')
  const version = ownDataValue(value, 'version')
  if (name !== '@napi-rs/canvas' || version !== EXPECTED_CANVAS_VERSION) {
    throw new TypeError('The exact PDF.js Canvas identity is unavailable.')
  }
  return Object.freeze({ name, version })
}

export function admitCanvasModule(value, packageManifest) {
  const identity = exactPackageIdentity(packageManifest)
  const required = ['createCanvas', 'DOMMatrix', 'ImageData', 'Path2D']
  if (
    value === null ||
    (typeof value !== 'object' && typeof value !== 'function') ||
    nodeTypes.isProxy(value) ||
    required.some((key) => typeof ownDataValue(value, key) !== 'function')
  ) {
    throw new TypeError('The exact PDF.js Canvas implementation is unavailable.')
  }
  return Object.freeze({ module: value, identity })
}

export function admitPdfjsModule(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    nodeTypes.isProxy(value) ||
    typeof ownDataValue(value, 'getDocument') !== 'function' ||
    ownDataValue(value, 'version') !== EXPECTED_PDFJS_VERSION
  ) {
    throw new TypeError('The exact PDF.js implementation is unavailable.')
  }
  return value
}

function makeCanvasFactory(canvasModule) {
  return class ExactCanvasFactory {
    create(width, height) {
      const canvas = canvasModule.createCanvas(width, height)
      return { canvas, context: canvas.getContext('2d') }
    }

    reset(surface, width, height) {
      surface.canvas.width = width
      surface.canvas.height = height
    }

    destroy(surface) {
      surface.canvas.width = 0
      surface.canvas.height = 0
      surface.canvas = null
      surface.context = null
    }
  }
}

function admitPdfPage(page) {
  if (
    page === null ||
    typeof page !== 'object' ||
    typeof page.cleanup !== 'function' ||
    typeof page.getViewport !== 'function' ||
    typeof page.render !== 'function'
  ) {
    throw new TypeError('PDF.js returned an invalid page handle.')
  }
}

function admitCanvasSurface(surface) {
  if (
    surface === null ||
    typeof surface !== 'object' ||
    typeof surface.encode !== 'function' ||
    typeof surface.getContext !== 'function'
  ) {
    throw new TypeError('Canvas returned an invalid raster surface.')
  }
}

function admitLoadingTask(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    !(value.promise instanceof Promise)
  ) {
    throw new TypeError('PDF.js returned an invalid loading task.')
  }
  return value
}

function admitDocument(value, maximumCount) {
  if (
    value === null ||
    typeof value !== 'object' ||
    !Number.isSafeInteger(value.numPages) ||
    value.numPages < 1 ||
    value.numPages > maximumCount ||
    typeof value.getPage !== 'function' ||
    typeof value.cleanup !== 'function'
  ) {
    throw new RangeError('PDF.js page count or document contract is invalid.')
  }
  return value
}

export async function renderPdfBytes({
  pdfBytes,
  policy,
  pdfjs,
  canvas,
  canvasPackage,
  sink,
}) {
  const admittedPolicy = admitRenderPolicy(policy)
  const admittedPdfjs = admitPdfjsModule(pdfjs)
  const admittedCanvas = admitCanvasModule(canvas, canvasPackage)
  if (typeof sink !== 'function') {
    throw new TypeError('A bounded per-page output sink is required.')
  }
  if (!Buffer.isBuffer(pdfBytes) || pdfBytes.byteLength === 0) {
    throw new TypeError('PDF input bytes are unavailable.')
  }
  if (pdfBytes.byteLength > admittedPolicy.input.maximumBytes) {
    throw new RangeError('PDF input exceeds the render input policy.')
  }
  let loadingTask
  let document
  try {
    loadingTask = admitLoadingTask(
      admittedPdfjs.getDocument({
        data: new Uint8Array(pdfBytes),
        CanvasFactory: makeCanvasFactory(admittedCanvas.module),
        cMapUrl: pathToFileURL(
          join(CORE_DOCUMENT_V5_PACK_ROOT, 'renderer/pdfjs/cmaps/'),
        ).href,
        iccUrl: pathToFileURL(
          join(CORE_DOCUMENT_V5_PACK_ROOT, 'renderer/pdfjs/iccs/'),
        ).href,
        wasmUrl: pathToFileURL(
          join(CORE_DOCUMENT_V5_PACK_ROOT, 'renderer/pdfjs/wasm/'),
        ).href,
        disableAutoFetch: true,
        disableFontFace: true,
        disableRange: true,
        disableStream: true,
        isEvalSupported: false,
        isImageDecoderSupported: false,
        isOffscreenCanvasSupported: false,
        maxImageSize: admittedPolicy.pages.maximumPixelsPerPage,
        stopAtErrors: true,
        useSystemFonts: false,
        useWorkerFetch: false,
      }),
    )
    document = await loadingTask.promise
    admitDocument(document, admittedPolicy.pages.maximumCount)

    const dimensions = []
    for (let number = 1; number <= document.numPages; number += 1) {
      const page = await document.getPage(number)
      try {
        admitPdfPage(page)
        const viewport = page.getViewport({
          scale: admittedPolicy.pages.rasterScale,
        })
        dimensions.push({ width: viewport.width, height: viewport.height })
      } finally {
        if (page && typeof page.cleanup === 'function') page.cleanup()
      }
    }
    const plan = planPageDimensions(dimensions, admittedPolicy)

    const evidence = []
    let totalOutputBytes = 0
    for (let number = 1; number <= document.numPages; number += 1) {
      const index = number - 1
      const page = await document.getPage(number)
      let surface
      try {
        admitPdfPage(page)
        const viewport = page.getViewport({
          scale: admittedPolicy.pages.rasterScale,
        })
        surface = admittedCanvas.module.createCanvas(
          plan[index].width,
          plan[index].height,
        )
        admitCanvasSurface(surface)
        const renderTask = page.render({
          canvas: surface,
          canvasContext: surface.getContext('2d'),
          viewport,
          background: admittedPolicy.pages.background,
        })
        if (
          renderTask === null ||
          typeof renderTask !== 'object' ||
          !(renderTask.promise instanceof Promise)
        ) {
          throw new TypeError('PDF.js returned an invalid page render task.')
        }
        await renderTask.promise
        const png = Buffer.from(await surface.encode('png'))
        totalOutputBytes += png.byteLength
        if (totalOutputBytes > admittedPolicy.pages.maximumTotalOutputBytes) {
          throw new RangeError('Rendered PNG bytes exceed total output policy.')
        }
        const pageEvidence = admitPngPageEvidence(plan[index], png)
        await sink(Object.freeze({ evidence: pageEvidence, bytes: png }))
        evidence.push(pageEvidence)
      } finally {
        if (surface) {
          surface.width = 0
          surface.height = 0
        }
        if (page && typeof page.cleanup === 'function') page.cleanup()
      }
    }
    return Object.freeze(evidence)
  } finally {
    try {
      if (document && typeof document.cleanup === 'function') {
        await document.cleanup()
      }
    } finally {
      if (loadingTask && typeof loadingTask.destroy === 'function') {
        await loadingTask.destroy()
      }
    }
  }
}
