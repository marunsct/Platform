/** Matura SDK for TypeScript: verify Matura tokens, check permissions, keep the matura_* contract tables in sync. */

export { Principal, type Claims, type PrincipalInit } from "./principal.js";
export {
  ALGORITHMS, InvalidToken, Verifier, bearer, type Algorithm, type Jwk, type JwkSet, type VerifierOptions,
} from "./tokens.js";
export {
  BadSignature, TOLERANCE_SECONDS, sign, verify, verify as verifySignature, type Body, type Secret, type VerifyOptions,
} from "./signatures.js";
export {
  CONTRACT_VERSION, Contract, InvalidEvent, ddl, type Dialect, type Executor, type Hook, type MaturaEvent,
  type QueryResult, type Statement,
} from "./contract.js";
export {
  CursorExpired, MaturaAPI, MaturaAPIError, Sync, snapshotEvents, type ChangesPage, type Credentials,
  type MaturaAPIOptions, type Placement, type Snapshot, type StorageRegistration, type SyncOptions, type Transaction,
} from "./feed.js";
export {
  Forbidden, authenticate, header, requirePermission, requireTenant, webhookHandler, type HeaderBag,
  type WebhookHandlerOptions, type WebhookResponse,
} from "./http.js";
export { FakeIssuer, signedEvent, type TokenOptions } from "./testing.js";
export { POSTGRES_SHARED_RLS_SQL, POSTGRES_SQL, SQLITE_SQL } from "./sql.js";
