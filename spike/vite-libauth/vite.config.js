import react from '@vitejs/plugin-react';
// libauth instantiates its WASM (secp256k1, sha256) with a top-level await -> es2022 or newer
export default { plugins: [react()], base: './', build: { target: 'es2022' } };
