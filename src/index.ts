import SurgeClient from './SurgeClient'
export { SurgeClient }
export * from './lib/types'
export * from './lib/errors'
export {
  navigatorLock,
  NavigatorLockAcquireTimeoutError,
  internals as lockInternals,
} from './lib/locks'
