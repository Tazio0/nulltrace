import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        monitor: resolve(__dirname, "monitor.html"),
        feed: resolve(__dirname, "threat-feed.html"),
        exports: resolve(__dirname, "exports.html"),
        system: resolve(__dirname, "system.html"),
        discord: resolve(__dirname, "discord.html")
      }
    }
  }
});
