import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#05070a",
        surface: "#0a0e14",
        elevated: "#111823",
        inset: "#030508",
        border: {
          subtle: "#1a2330",
          DEFAULT: "#2a3646",
          strong: "#3a4a5e",
          focus: "#00d9ff",
        },
        text: {
          primary: "#e8eef6",
          secondary: "#8a97a8",
          tertiary: "#5a6675",
          disabled: "#3a4454",
          inverse: "#05070a",
        },
        accent: {
          DEFAULT: "#00d9ff",
          dim: "#0099b8",
        },
        sev: {
          critical: "#ff2d55",
          high: "#ff7a1a",
          medium: "#ffb020",
          low: "#4a9eff",
          info: "#6b7885",
        },
        status: {
          success: "#00e07a",
          warn: "#ffb020",
          error: "#ff2d55",
          idle: "#4a5568",
        },
        layer: {
          surface: "#4a9eff",
          deep: "#a855f7",
          dark: "#ff2d55",
          physical: "#00e07a",
          ai: "#00d9ff",
          brand: "#ff7a1a",
          federation: "#eab308",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "SF Mono", "Consolas", "monospace"],
      },
      fontSize: {
        xs: "0.6875rem",
        sm: "0.8125rem",
        base: "0.875rem",
        lg: "1rem",
        xl: "1.25rem",
        "2xl": "1.5rem",
        "3xl": "2rem",
        "4xl": "2.75rem",
        "5xl": "3.5rem",
      },
      borderRadius: {
        sm: "4px",
        md: "6px",
        lg: "8px",
        xl: "12px",
      },
      boxShadow: {
        sm: "0 1px 2px rgba(0,0,0,0.4)",
        md: "0 4px 12px rgba(0,0,0,0.5)",
        lg: "0 12px 32px rgba(0,0,0,0.6)",
        glowCritical: "0 0 12px rgba(255,45,85,0.5)",
        glowCyan: "0 0 12px rgba(0,217,255,0.4)",
      },
      transitionTimingFunction: {
        expo: "cubic-bezier(0.16, 1, 0.3, 1)",
      },
      animation: {
        "pulse-live": "pulse-live 2s ease-in-out infinite",
        "slide-in-top": "slide-in-top 200ms cubic-bezier(0.16, 1, 0.3, 1)",
      },
      keyframes: {
        "pulse-live": {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.6", transform: "scale(0.85)" },
        },
        "slide-in-top": {
          from: { opacity: "0", transform: "translateY(-8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
