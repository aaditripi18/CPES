// CPES palette: graphite surfaces, one violet interaction accent, severity colours
// with fixed meanings. Values are CSS variables (src/index.css) so light and dark themes share one token set.
const MONO = ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"];
const SANS = ["Hanken Grotesk", "ui-sans-serif", "system-ui", "sans-serif"];

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "bg": "rgb(var(--c-bg) / <alpha-value>)",
        "panel": "rgb(var(--c-panel) / <alpha-value>)",
        "raised": "rgb(var(--c-raised) / <alpha-value>)",
        "hover": "rgb(var(--c-hover) / <alpha-value>)",
        "line": "rgb(var(--c-line) / <alpha-value>)",
        "line-strong": "rgb(var(--c-line-strong) / <alpha-value>)",
        "ink": "rgb(var(--c-ink) / <alpha-value>)",
        "muted": "rgb(var(--c-muted) / <alpha-value>)",
        "faint": "rgb(var(--c-faint) / <alpha-value>)",
        "accent": "rgb(var(--c-accent) / <alpha-value>)",
        "accent-dim": "rgb(var(--c-accent-dim) / <alpha-value>)",
        "detect": "rgb(var(--c-detect) / <alpha-value>)",
        "detect-dim": "rgb(var(--c-detect-dim) / <alpha-value>)",
        "warn": "rgb(var(--c-warn) / <alpha-value>)",
        "warn-dim": "rgb(var(--c-warn-dim) / <alpha-value>)",
        "ok": "rgb(var(--c-ok) / <alpha-value>)",
        "ok-dim": "rgb(var(--c-ok-dim) / <alpha-value>)",
        "info": "rgb(var(--c-info) / <alpha-value>)",
        "info-dim": "rgb(var(--c-info-dim) / <alpha-value>)",
      },
      fontFamily: { sans: SANS, mono: MONO },
      fontSize: { "2xs": ["0.6875rem", { lineHeight: "1rem" }] },
      borderRadius: { DEFAULT: "4px", md: "6px", lg: "8px" },
    },
  },
};
