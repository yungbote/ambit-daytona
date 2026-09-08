# General file tools

This optional workspace-image layer adds tools the agent can choose directly:

- libvips for demand-driven image processing, regions, thumbnails and tiled images.
- MarkItDown and its local file classifier for structured text/Markdown extraction.
- Tika for local content detection, metadata and text/Markdown extraction through
  its existing parser registry, including files whose extension is unhelpful.

These tools complement the existing Python, data libraries, MuPDF, Poppler,
LibreOffice, Pandoc, ImageMagick, FFmpeg and Tesseract environment. They do not
select a workflow for the agent, replace original files, require OCR, or replace
native document inputs. A model may use native inputs, these tools, ordinary
programs, or combinations of them.

`file-tools.lock.json` owns the dependency inputs. The separate Python environment
at `/opt/ambit/file-tools/python` keeps MarkItDown's Mammoth requirement from
changing the existing default Python environment. Downloaded Python wheel hashes
are pinned; optional cloud/transcription/model-client plugins are not installed.
The Tika distribution is pinned by size and SHA-256, verified against Apache's
published SHA-512. Its license and notices remain with the distribution.

The `tika` launcher preserves relative file paths and supplies a default config
with automatic OCR disabled. Tesseract remains available, and Tika's normal
`--config` option remains available when different parsing behavior is useful.
The distributed parser inventory and network-disabled checks must confirm that
no external VLM backend is implicitly enabled. No Tika server is installed.

Original source bytes, native text, extracted Markdown, OCR and rendered pixels
have different meanings. Empty extraction does not establish that a file is
empty. Rendered previews do not prove every annotation is readable. Full dataset
analysis remains available through ordinary code and the existing data engines.

Build from a committed source archive with this directory as the Docker context:

```sh
docker build --file Dockerfile --build-arg BUILD_SOURCE_REVISION=COMMIT_SHA \
  --tag ambit-general-file-tools:COMMIT_SHA .
```

The default immutable parent is the current ordinary workspace image, allowing
file tooling to be qualified independently of browser publication. A combined
image must record its actual parent and rerun the relevant inherited checks.
Image inventory is generated from installed package metadata through the shared
workspace inventory producer; it describes preinstalled image contents, not a
promise that a later model-authored package installation left them unchanged.

Tesseract defaults to one OpenMP thread only when neither OMP_THREAD_LIMIT nor
OMP_NUM_THREADS is set. Both caller controls remain available. A controlled
two-CPU/4-GiB benchmark of147 OCR invocations retained byte-identical output;
parallel six-page batches improved2.76–3.24× on the tested fixtures. This is a
Tesseract-specific default, not a limit on the model, worker count, or other
libraries. See the reusable conformance/ocr-benchmark.py and retained release
evidence for quality limits and raw measurements.

Current status: implementation candidate. Local conformance, measured throughput
and memory, exact final image publication, runtime inventory binding, and normal
production chat acceptance must be recorded before claiming availability.

Primary references: [libvips](https://www.libvips.org/),
[MarkItDown 0.1.7](https://github.com/microsoft/markitdown/releases/tag/v0.1.7),
[Tika 4.0](https://tika.apache.org/download.html).
