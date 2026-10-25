import test from "node:test";
import assert from "node:assert/strict";
import { assertThreadOwnership } from "../src/thread-ownership.js";
import { CopilotAccessError } from "../src/copilot-errors.js";
test("allows only matching tenant and actor",()=>assert.doesNotThrow(()=>assertThreadOwnership({tenant_id:"t1",actor_id:"u1",case_id:"c1"},{tenant_id:"t1",user_id:"u1",case_id:"c1"})));
test("denies cross-actor and cross-tenant access",()=>{for(const thread of [{tenant_id:"t1",actor_id:"u2"},{tenant_id:"t2",actor_id:"u1"}])assert.throws(()=>assertThreadOwnership(thread,{tenant_id:"t1",user_id:"u1"}),CopilotAccessError)});
test("denies mismatched case",()=>assert.throws(()=>assertThreadOwnership({tenant_id:"t1",actor_id:"u1",case_id:"c2"},{tenant_id:"t1",user_id:"u1",case_id:"c1"}),CopilotAccessError));
