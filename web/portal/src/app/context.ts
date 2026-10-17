import { createContext, useContext } from "react";
import type { Auth, PortalConfig } from "../lib/auth";
import type { Endpoints } from "../lib/endpoints";

export interface AppContextValue {
  config: PortalConfig;
  auth: Auth;
  ep: Endpoints;
}

export const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const v = useContext(AppContext);
  if (!v) throw new Error("useApp outside AppContext");
  return v;
}
