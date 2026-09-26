export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "denali.theme";

export function resolveTheme(storedTheme: string | null, prefersDark: boolean): Theme {
  if (storedTheme === "light" || storedTheme === "dark") return storedTheme;
  return prefersDark ? "dark" : "light";
}

export function nextTheme(theme: Theme): Theme {
  return theme === "dark" ? "light" : "dark";
}

export function currentTheme(root: Pick<HTMLElement, "classList"> = document.documentElement): Theme {
  return root.classList.contains("dark") ? "dark" : "light";
}

export function applyTheme(
  theme: Theme,
  { persist = true }: { persist?: boolean } = {},
): void {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.dataset.theme = theme;
  root.style.colorScheme = theme;

  if (!persist) return;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Theme selection remains active when browser storage is unavailable.
  }
}

export function initializeTheme(): Theme {
  let storedTheme: string | null = null;
  try {
    storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Fall back to the system preference when browser storage is unavailable.
  }
  const theme = resolveTheme(storedTheme, window.matchMedia("(prefers-color-scheme: dark)").matches);
  applyTheme(theme, { persist: false });
  return theme;
}
