import {AriesAskar} from 'aries-askar-shared'

import {ariesAskarReactNative} from '../register'

export class ReactNativeAriesAskar implements AriesAskar {
  private promisify = (method: (cb: (err: number) => void) => void): Promise<void> => {
    return new Promise((resolve, reject) => {
      const _cb = (err: number) => {
        if (err !== 0) reject(this.getCurrentError())
        resolve()
      }

      method(_cb)
    })
  }

  private promisifyWithResponse = <T>(
    method: (cb: (err: number, response: string) => void) => void,
    isStream = false
  ): Promise<T> => {
    return new Promise((resolve, reject) => {
      const _cb = (err: number, response: string) => {
        if (err !== 0) reject(this.getCurrentError())

        try {
          // this is required to add array brackets, and commas, to an invalid json object that
          //should be a list
          const mappedResponse = isStream ? '[' + response.replace(/\n/g, ',') + ']' : response
          resolve(JSON.parse(mappedResponse) as T)
        } catch (error) {
          resolve(JSON.parse(response) as T)
        }
      }

      method(_cb)
    })
  }

  public getCurrentError(): string {
    return ariesAskarReactNative.getCurrentError({})
  }
}
