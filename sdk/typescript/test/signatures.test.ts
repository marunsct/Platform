import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { BadSignature, sign, verifySignature } from "../src/index.js";

describe("webhook signatures", () => {
  it("round-trips within the tolerance", () => {
    const h = sign("k", "{}", 1000);
    assert.match(h, /^t=1000,v1=[0-9a-f]{64}$/);
    verifySignature("k", "{}", h, { now: 1100 });
    verifySignature("k", Buffer.from("{}"), h, { now: 1300 });
    assert.throws(() => verifySignature("k", "{}", h, { now: 2000 }), /too old/);
    assert.throws(() => verifySignature("k", "{}", h, { now: 700 - 1 }), /too old/);
    verifySignature("k", "{}", h, { now: 2000, toleranceSeconds: 1000 });
  });

  it("accepts any v1 during a secret rotation", () => {
    const old = sign("old", "body", 1000).split(",")[1]!;
    const next = sign("new", "body", 1000).split(",")[1]!;
    for (const secret of ["old", "new"]) verifySignature(secret, "body", `t=1000,${old}, ${next}`, { now: 1000 });
    assert.throws(() => verifySignature("other", "body", `t=1000,${old},${next}`, { now: 1000 }), BadSignature);
  });

  it("refuses malformed headers", () => {
    for (const h of [undefined, "", "v1=abc", "t=abc,v1=00", "t=1000", "t=-1,v1=00", "t=1000,v1="]) {
      assert.throws(() => verifySignature("k", "{}", h, { now: 1000 }), BadSignature, String(h));
    }
    const good = sign("k", "{}", 1000);
    assert.throws(() => verifySignature("k", "{} ", good, { now: 1000 }), /does not match/);
    assert.throws(() => verifySignature("k", "{}", good.toUpperCase().replace("T=", "t=").replace("V1", "v1"), { now: 1000 }), /does not match/);
  });

  it("signs with the current time by default", () => {
    const h = sign(Buffer.from("k"), "{}");
    verifySignature("k", "{}", h);
  });
});
