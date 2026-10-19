import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";

export type Theme = "dark" | "light";

const KEY = "cpes-theme";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* storage blocked: fall back to the OS preference */
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

const ThemeContext = createContext<{ theme: Theme; toggle: () => void }>({ theme: "dark", toggle: () => {} });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    document.documentElement.classList.toggle("light", theme === "light");
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* not persisted; still applied for this page */
    }
  }, [theme]);
  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  return <ThemeContext.Provider value={{ theme, toggle }}>{children}</ThemeContext.Provider>;
}

export const useTheme = () => useContext(ThemeContext);

/** Literal colours for canvas/SVG props that cannot take CSS variables (React Flow). */
export const GRAPH_COLORS: Record<Theme, { edge: string; ghost: string; grid: string; node: string; detect: string; mask: string; panel: string }> = {
  dark: { edge: "#3b4658", ghost: "#5d6778", grid: "#1b212c", node: "#5d6778", detect: "#ff7b6b", mask: "#0b0e13cc", panel: "#11151c" },
  light: { edge: "#b4bcc8", ghost: "#8d96a5", grid: "#e4e8ee", node: "#a3abb8", detect: "#d1453a", mask: "#f5f6f8cc", panel: "#ffffff" },
};
