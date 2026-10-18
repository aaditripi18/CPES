// CPES palette: graphite surfaces, one violet interaction accent, severity colours
// with fixed meanings (see docs/dashboard/stitch_prompts.md, prompt 0).
const MONO = ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"];
const SANS = ["Hanken Grotesk", "ui-sans-serif", "system-ui", "sans-serif"];

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0e13",
        panel: "#11151c",
        raised: "#161b24",
        hover: "#1b212c",
        line: "#222a36",
        "line-strong": "#2e3747",
        ink: "#e4e8ef",
        muted: "#8a94a6",
        faint: "#5d6778",
        accent: "#a78bfa",
        "accent-dim": "#2a2347",
        detect: "#ff7b6b",
        "detect-dim": "#3a1d1b",
        warn: "#f2b84b",
        "warn-dim": "#3a2d12",
        ok: "#7fd1a8",
        "ok-dim": "#15301f",
        info: "#7cb7ff",
      },
      fontFamily: { sans: SANS, mono: MONO },
      fontSize: { "2xs": ["0.6875rem", { lineHeight: "1rem" }] },
      borderRadius: { DEFAULT: "4px", md: "6px", lg: "8px" },
    },
  },
};
