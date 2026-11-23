import assert from "node:assert/strict";
import { repoResponseOrder } from "../src/lib/repo-response-order.ts";
assert.doesNotMatch(repoResponseOrder([{ category: "authorization", title: "Route authentication not seen" }]).join(" "), /revoke/i);
assert.match(repoResponseOrder([{ category: "secrets", title: "Potential key" }, { category: "dependencies", title: "Advisory" }])[0], /revoke/i);
console.log("Finding-specific response order checks passed.");
