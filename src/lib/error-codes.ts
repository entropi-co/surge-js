/**
 * Known error codes. Note that the server may also return other error codes
 * not included in this list (if the client library is older than the version
 * on the server).
 */
export type ErrorCode =
  | 'unknown'
  | 'unexpected_failure'
  | 'database_failure'
  | 'invalid_json'
  | 'missing_field'
  | 'invalid_field'
  | 'invalid_credentials'
  | 'conflict'
  | 'invalid_grant_type'
  | 'disabled_grant_type'
  | 'invalid_provider_type'
  | 'bad_oauth2_state'
  | 'bad_oauth2_callback'
  | 'provider_oauth2_unsupported'
  | 'user_not_found'
  | 'refresh_token_not_found'
  | 'refresh_token_revoked'
  | 'no_authorization'
  | 'bad_jwt'