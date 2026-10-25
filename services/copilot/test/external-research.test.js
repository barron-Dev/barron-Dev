import test from "node:test";
import assert from "node:assert/strict";
import { normalizeExternalQuery, normalizeBraveResults } from "../src/external-research.js";
test("normalizes and bounds query",()=>{assert.equal(normalizeExternalQuery("  hello   world  "),"hello world");assert.equal(normalizeExternalQuery("x".repeat(900)).length,500);assert.equal(normalizeExternalQuery(null),"")});
test("only emits safe HTTP(S) source URLs",()=>{const results=normalizeBraveResults({web:{results:[{title:"ok",url:"https://example.org/a",description:"source"},{title:"bad",url:"javascript:alert(1)"},{title:"bad2",url:"https://user:pass@example.org"}]}},5);assert.equal(results.length,1);assert.equal(results[0].url,"https://example.org/a")});
