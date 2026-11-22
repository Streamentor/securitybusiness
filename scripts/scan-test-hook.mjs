import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";

// Next supplies the server-only and @/ aliases in production. Resolve them for
// these isolated Node tests without loading the framework or any credentials.
const sourceRoot = new URL("../src/", import.meta.url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: "data:text/javascript,export{}", shortCircuit: true };
    if (specifier.startsWith("@/")) return { url: new URL(`${specifier.slice(2)}.ts`, sourceRoot).href, shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) {
      return { format: "module", source: stripTypeScriptTypes(readFileSync(new URL(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
