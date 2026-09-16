import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#05070a",
        surface: "#0a0e14",
        elevated: "#111823",
        inset: "#030508",
        border: "#1a2330",
        cyan: "#00d9ff",
        critical: "#ff2d55",
        high: "#ff7a1a",
        medium: "#ffb020",
        low: "#4a9eff",
        success: "#00e07a",
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "SF Mono", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
