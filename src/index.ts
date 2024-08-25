
import SurgeClient from './SurgeClient'
import AuthClient from './AuthClient'
export { SurgeClient, AuthClient }
export * from './lib/types'
export * from './lib/errors'
export {
  navigatorLock,
  NavigatorLockAcquireTimeoutError,
  internals as lockInternals,
} from './lib/locks'
