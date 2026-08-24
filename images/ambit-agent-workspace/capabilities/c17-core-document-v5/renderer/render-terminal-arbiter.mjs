export class RenderTerminalArbiter {
  #controller = new AbortController()
  #reason = null
  #state = 'open'

  get signal() {
    return this.#controller.signal
  }

  get state() {
    return this.#state
  }

  get reason() {
    return this.#reason
  }

  cancel(reason) {
    if (this.#state !== 'open') return false
    this.#reason = exactReason(reason, 'Render cancellation')
    this.#state = 'cancelled'
    this.#controller.abort(this.#reason)
    return true
  }

  fail(reason) {
    if (!['cancelled', 'open', 'success-committed'].includes(this.#state)) {
      return false
    }
    this.#reason = exactReason(reason, 'Render failure')
    this.#state = 'failed'
    if (!this.#controller.signal.aborted) this.#controller.abort(this.#reason)
    return true
  }

  commitSuccess() {
    if (this.#state !== 'open') return false
    this.#state = 'success-committed'
    return true
  }

  completeSuccess() {
    if (this.#state !== 'success-committed') {
      throw new TypeError('Render success cannot complete before its commit point.')
    }
    this.#state = 'succeeded'
  }
}

function exactReason(value, label) {
  if (!(value instanceof Error)) {
    throw new TypeError(`${label} reason must be an Error.`)
  }
  return value
}
