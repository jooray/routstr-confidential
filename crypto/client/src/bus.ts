// The driver's message bus: control frames from the node, by type, in order.

type Waiter = { types: string[]; res: (m: any) => void }

export class Bus {
  private pending = new Map<string, unknown[]>()
  private waiters: Waiter[] = []
  emit(msg: any) {
    const i = this.waiters.findIndex((w) => w.types.includes(msg.type))
    if (i >= 0) this.waiters.splice(i, 1)[0]!.res(msg)
    else {
      const p = this.pending.get(msg.type) ?? []
      p.push(msg)
      this.pending.set(msg.type, p)
    }
  }
  /**
   * The next message of any of `types`. `cancel()` withdraws the wait: a
   * waiter that lost a race must not take a message a later wait needs.
   */
  take(types: string[]): { promise: Promise<any>; cancel: () => void } {
    for (const type of types) {
      const p = this.pending.get(type)
      if (p && p.length) return { promise: Promise.resolve(p.shift()), cancel: () => {} }
    }
    let w!: Waiter
    const promise = new Promise<any>((res) => {
      w = { types, res }
      this.waiters.push(w)
    })
    return {
      promise,
      cancel: () => {
        const i = this.waiters.indexOf(w)
        if (i >= 0) this.waiters.splice(i, 1)
      },
    }
  }
  /** The next message of `type`, for a wait that never loses a race. */
  wait(type: string): Promise<any> {
    return this.take([type]).promise
  }
}

/**
 * The next message of `type` (or of any of several types: the message's own
 * `type` tells which), unless one of `stops` rejects first or `ms` pass. The
 * wait is withdrawn from the bus however it ends.
 */
export async function waitMsg(bus: Bus, type: string | string[], ms: number, ...stops: Promise<unknown>[]): Promise<any> {
  const types = typeof type === 'string' ? [type] : type
  const t = bus.take(types)
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      t.promise,
      ...stops,
      new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new Error(`timeout waiting for ${types.join('/')}`)), ms)
      }),
    ])
  } finally {
    clearTimeout(timer)
    t.cancel()
  }
}
