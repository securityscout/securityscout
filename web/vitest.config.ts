import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  test: {
    environment: "jsdom",
    environmentOptions: { url: "http://localhost:3000/" },
    setupFiles: ["./src/test-setup.ts"],
  },
});
