// The site: a static build, every check in the browser. libauth starts its WASM with a top-level await → es2022.
// Two pages: the Countersign site, and a separate demo app that signs people in with the library (spec §9).
import { fileURLToPath } from "node:url";

const page = (path) => fileURLToPath(new URL(path, import.meta.url));
export default {
  root: "app",
  base: "./",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
    rolldownOptions: { input: { site: page("app/index.html"), login: page("app/demo-login/index.html") } },
  },
};
