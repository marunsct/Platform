// PKCE (RFC 7636) helpers for the authorization code flow as a public client.

export function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomString(byteLength = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function challengeFor(verifier: string): Promise<string> {
  return base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
}

export interface Pkce {
  verifier: string;
  challenge: string;
}

export async function createPkce(): Promise<Pkce> {
  const verifier = randomString(32); // 43 characters, inside RFC 7636's 43–128
  return { verifier, challenge: await challengeFor(verifier) };
}
