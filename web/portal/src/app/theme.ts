export type ThemeChoice = "light" | "dark" | "system";
const KEY = "matura.portal.theme";

export function readTheme(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(choice: ThemeChoice): void {
  if (choice === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = choice;
  try {
    if (choice === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, choice);
  } catch {
    // private window: the choice lasts for this page only
  }
}

const LAST_TENANT = "matura.portal.tenant";

export function lastTenant(): string | null {
  try {
    return localStorage.getItem(LAST_TENANT);
  } catch {
    return null;
  }
}

export function rememberTenant(tid: string): void {
  try {
    localStorage.setItem(LAST_TENANT, tid);
  } catch {
    // ignore
  }
}
