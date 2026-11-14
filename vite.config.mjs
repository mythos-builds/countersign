// The pay page: a static site, every check in the browser. libauth starts its WASM with a top-level await → es2022.
export default { root: "app", base: "./", build: { outDir: "../dist", emptyOutDir: true, target: "es2022" } };
