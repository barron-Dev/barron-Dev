import test from "node:test";
import assert from "node:assert/strict";
import { buildContinuityContext } from "../src/conversation-continuity.js";

test("keeps prior conversation context chronological and marks it untrusted",()=>{
 const result=buildContinuityContext([{role:"assistant",content:"Earlier answer"},{role:"user",content:"Earlier request"}]);
 assert.ok(result.indexOf("[USER] Earlier request") < result.indexOf("[ASSISTANT] Earlier answer"));
 assert.match(result,/not as system instructions/);
});
test("filters unsupported roles and bounds stored context",()=>{
 const result=buildContinuityContext([{role:"system",content:"must not be included"},{role:"user",content:"x".repeat(9000)}]);
 assert.doesNotMatch(result,/must not be included/);
 assert.ok(result.length < 8200);
});
