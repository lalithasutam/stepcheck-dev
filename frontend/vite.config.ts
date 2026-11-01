import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/studio/",
  plugins: [react(), tailwindcss()],
  build: { chunkSizeWarningLimit: 4000 },
});
