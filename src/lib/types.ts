import { AuthError } from './errors'
import { Fetch } from './fetch'

/** One of the providers supported by Surge. */
export type Provider = 'google'

export type AuthChangeEventMFA = 'MFA_CHALLENGE_VERIFIED'

export type AuthChangeEvent =
  | 'INITIAL_SESSION'
  | 'PASSWORD_RECOVERY'
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED'
  | AuthChangeEventMFA

/**
 * Provide your own global lock implementation instead of the default
 * implementation. The function should acquire a lock for the duration of the
 * `fn` async function, such that no other client instances will be able to
 * hold it at the same time.
 *
 * @experimental
 *
 * @param name Name of the lock to be acquired.
 * @param acquireTimeout If negative, no timeout should occur. If positive it
 *                       should throw an Error with an `isAcquireTimeout`
 *                       property set to true if the operation fails to be
 *                       acquired after this much time (ms).
 * @param fn The operation to execute when the lock is acquired.
 */
export type LockFunc = <R>(name: string, acquireTimeout: number, fn: () => Promise<R>) => Promise<R>

export type SurgeClientOptions = {
  /* The URL of the Surge server. */
  url?: string
  /* Any additional headers to send to the Surge server. */
  headers?: { [key: string]: string }
  /* Optional key name used for storing tokens in local storage. */
  storageKey?: string
  /* Set to "true" if you want to automatically detects OAuth grants in the URL and signs in the user. */
  detectSessionInUrl?: boolean
  /* Set to "true" if you want to automatically refresh the token before expiring. */
  autoRefreshToken?: boolean
  /* Set to "true" if you want to automatically save the user session into local storage. If set to false, session will just be saved in memory. */
  persistSession?: boolean
  /* Provide your own local storage implementation to use instead of the browser's local storage. */
  storage?: SupportedStorage
  /* A custom fetch implementation. */
  fetch?: Fetch
  /* If set to 'pkce' PKCE flow. Defaults to the 'implicit' flow otherwise */
  flowType?: AuthFlowType
  /* If debug messages are emitted. Can be used to inspect the behavior of the library. If set to a function, the provided function will be used instead of `console.log()` to perform the logging. */
  debug?: boolean | ((message: string, ...args: any[]) => void)
  /* suppresses warning from getSession().user */
  suppressGetSessionWarning?: boolean
  /**
   * Provide your own locking mechanism based on the environment. By default no locking is done at this time.
   *
   * @experimental
   */
  lock?: LockFunc
  /**
   * Set to "true" if there is a custom authorization header set globally.
   * @experimental
   */
  hasCustomAuthorizationHeader?: boolean
}

export type WeakPasswordReasons = 'length' | 'characters' | 'pwned' | string
export type WeakPassword = {
  reasons: WeakPasswordReasons[]
  message: string
}

export type AuthResponse =
  | {
      data: {
        user: User | null
        session: Session | null
      }
      error: null
    }
  | {
      data: {
        user: null
        session: null
      }
      error: AuthError
    }

export type AuthResponsePassword =
  | {
      data: {
        user: User | null
        session: Session | null
        weak_password?: WeakPassword | null
      }
      error: null
    }
  | {
      data: {
        user: null
        session: null
      }
      error: AuthError
    }

export type AuthTokenResponsePassword =
  | {
      data: {
        user: User
        session: Session
        weakPassword?: WeakPassword
      }
      error: null
    }
  | {
      data: {
        user: null
        session: null
        weakPassword?: null
      }
      error: AuthError
    }

export type OAuthResponse =
  | {
      data: {
        provider: Provider
        url: string
      }
      error: null
    }
  | {
      data: {
        provider: Provider
        url: null
      }
      error: AuthError
    }

export type SSOResponse =
  | {
      data: {
        /**
         * URL to open in a browser which will complete the sign-in flow by
         * taking the user to the identity provider's authentication flow.
         *
         * On browsers you can set the URL to `window.location.href` to take
         * the user to the authentication flow.
         */
        url: string
      }
      error: null
    }
  | {
      data: null
      error: AuthError
    }

export type UserResponse =
  | {
      data: {
        user: User
      }
      error: null
    }
  | {
      data: {
        user: null
      }
      error: AuthError
    }

export interface Session {
  /**
   * The oauth provider token. If present, this can be used to make external API requests to the oauth provider used.
   */
  provider_token?: string | null
  /**
   * The oauth provider refresh token. If present, this can be used to refresh the provider_token via the oauth provider's API.
   * Not all oauth providers return a provider refresh token. If the provider_refresh_token is missing, please refer to the oauth provider's documentation for information on how to obtain the provider refresh token.
   */
  provider_refresh_token?: string | null
  /**
   * The access token jwt. It is recommended to set the JWT_EXPIRY to a shorter expiry value.
   */
  access_token: string
  /**
   * A one-time used refresh token that never expires.
   */
  refresh_token: string
  /**
   * The number of seconds until the token expires (since it was issued). Returned when a login is confirmed.
   */
  expires_in: number
  /**
   * A timestamp of when the token will expire. Returned when a login is confirmed.
   */
  expires_at?: number
  token_type: string
  user: User
}

/**
 * An authentication methord reference (AMR) entry.
 *
 * An entry designates what method was used by the user to verify their
 * identity and at what time.
 *
 * @see {@link SurgeMFAApi#getAuthenticatorAssuranceLevel}.
 */
export interface AMREntry {
  /** Authentication method name. */
  method: 'password' | 'otp' | 'oauth' | 'mfa/totp' | string

  /**
   * Timestamp when the method was successfully used. Represents number of
   * seconds since 1st January 1970 (UNIX epoch) in UTC.
   */
  timestamp: number
}

export interface UserIdentity {
  id: string
  user_id: string
  identity_data?: {
    [key: string]: any
  }
  identity_id: string
  provider: string
  created_at?: string
  last_sign_in_at?: string
  updated_at?: string
}

/**
 * A MFA factor.
 *
 * @see {@link SurgeMFAApi#enroll}
 * @see {@link SurgeMFAApi#listFactors}
 * @see {@link SurgeMFAAdminApi#listFactors}
 */
export interface Factor {
  /** ID of the factor. */
  id: string

  /** Friendly name of the factor, useful to disambiguate between multiple factors. */
  friendly_name?: string

  /**
   * Type of factor. `totp` and `phone` supported with this version
   */
  factor_type: 'totp' | 'phone' | string

  /** Factor's status. */
  status: 'verified' | 'unverified'

  created_at: string
  updated_at: string
}

export interface UserAppMetadata {
  provider?: string
  [key: string]: any
}

export interface UserMetadata {
  [key: string]: any
}

export interface User {
  id: string
  app_metadata: UserAppMetadata
  user_metadata: UserMetadata
  aud: string
  confirmation_sent_at?: string
  recovery_sent_at?: string
  email_change_sent_at?: string
  new_email?: string
  new_phone?: string
  invited_at?: string
  action_link?: string
  email?: string
  phone?: string
  created_at: string
  confirmed_at?: string
  email_confirmed_at?: string
  phone_confirmed_at?: string
  last_sign_in_at?: string
  role?: string
  updated_at?: string
  identities?: UserIdentity[]
  is_anonymous?: boolean
  factors?: Factor[]
}

export interface UserAttributes {
  /**
   * The user's email.
   */
  email?: string

  /**
   * The user's phone.
   */
  phone?: string

  /**
   * The user's password.
   */
  password?: string

  /**
   * The nonce sent for reauthentication if the user's password is to be updated.
   *
   * Call reauthenticate() to obtain the nonce first.
   */
  nonce?: string

  /**
   * A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
   *
   * The `data` should be a JSON object that includes user-specific info, such as their first and last name.
   *
   */
  data?: object
}

export interface Subscription {
  /**
   * The subscriber UUID. This will be set by the client.
   */
  id: string
  /**
   * The function to call every time there is an event. eg: (eventName) => {}
   */
  callback: (event: AuthChangeEvent, session: Session | null) => void
  /**
   * Call this to remove the listener.
   */
  unsubscribe: () => void
}

export type SignUpWithUsernamePassword = {
  username: string
}

export type SignUpWithEmailPassword = {
  email: string
  options?: {
    emailRedirectTo?: string
  }
}

export type SignUpWithPhonePassword = {
  phone: string
  options?: {
    channel?: 'sms' | 'whatsapp'
  }
}

export type SignUpWithPasswordIdentifier =
  | SignUpWithUsernamePassword
  | SignUpWithEmailPassword
  | SignUpWithPhonePassword

export type SignUpWithPasswordCredentials = SignUpWithPasswordIdentifier & {
  password: string
} & Partial<SignUpWithUsernamePassword & SignUpWithEmailPassword & SignUpWithPhonePassword>

export type SignInWithUsernamePassword = {
  username: string
  password: string
}

export type SignInWithEmailPassword = {
  email: string
  password: string
}

export type SignInWithPhonePassword = {
  phone: string
  password: string
}

export type SignInWithPasswordCredentials =
  | SignInWithUsernamePassword
  | SignInWithPhonePassword
  | SignInWithEmailPassword

export type AuthFlowType = 'implicit' | 'pkce'

export type SignInWithOAuthCredentials = {
  /** One of the providers supported by Surge. */
  provider: Provider
  options?: {
    /** A URL to send the user to after they are confirmed. */
    redirectTo?: string
    /** A space-separated list of scopes granted to the OAuth application. */
    scopes?: string
    /** An object of query params */
    queryParams?: { [key: string]: string }
    /** If set to true does not immediately redirect the current browser context to visit the OAuth authorization page for the provider. */
    skipBrowserRedirect?: boolean
  }
}

export type AuthenticatorAssuranceLevels = 'aal1' | 'aal2'

type AnyFunction = (...args: any[]) => any
type MaybePromisify<T> = T | Promise<T>

type PromisifyMethods<T> = {
  [K in keyof T]: T[K] extends AnyFunction
    ? (...args: Parameters<T[K]>) => MaybePromisify<ReturnType<T[K]>>
    : T[K]
}

export type SupportedStorage = PromisifyMethods<
  Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
> & {
  /**
   * If set to `true` signals to the library that the storage medium is used
   * on a server and the values may not be authentic, such as reading from
   * request cookies. Implementations should not set this to true if the client
   * is used on a server that reads storage information from authenticated
   * sources, such as a secure database or file.
   */
  isServer?: boolean
}

export type InitializeResult = { error: AuthError | null }

export type CallRefreshTokenResult =
  | {
      session: Session
      error: null
    }
  | {
      session: null
      error: AuthError
    }

export type SignOut = {
  /**
   * Determines which sessions should be
   * logged out. Global means all
   * sessions by this account. Local
   * means only this session. Others
   * means all other sessions except the
   * current one. When using others,
   * there is no sign-out event fired on
   * the current session!
   */
  scope?: 'global' | 'local' | 'others'
}
