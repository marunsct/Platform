import { StrictMode, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import "./styles.css";
import { AppContext, type AppContextValue } from "./app/context";
import { BASE_PATH, makeRouter } from "./app/router";
import { applyTheme, readTheme } from "./app/theme";
import { ApiError, createApiClient } from "./lib/api";
import { DevAuth, OidcAuth, RedirectingError, type PortalConfig } from "./lib/auth";
import { endpoints } from "./lib/endpoints";
import { DevSignIn } from "./pages/DevSignIn";
import { Button, Spinner, ToastProvider } from "./ui";

applyTheme(readTheme());
const rootEl = document.getElementById("root")!;
const root = createRoot(rootEl);

function Centered({ children }: { children: ReactNode }) {
  return <div className="flex min-h-dvh flex-col items-center justify-center gap-3 px-4 text-center text-[13px] text-fg-muted">{children}</div>;
}

function Failure({ title, detail }: { title: string; detail: string }) {
  return (
    <Centered>
      <p className="text-sm font-medium text-fg">{title}</p>
      <p className="max-w-sm">{detail}</p>
      <Button onClick={() => location.assign(BASE_PATH + "/")}>Try again</Button>
    </Centered>
  );
}

function retry(count: number, err: unknown): boolean {
  if (err instanceof ApiError && err.status >= 400 && err.status < 500) return false;
  return !(err instanceof RedirectingError) && count < 2;
}

function App({ ctx }: { ctx: AppContextValue }) {
  const [qc] = useState(() => new QueryClient({ defaultOptions: { queries: { retry, refetchOnWindowFocus: true, staleTime: 15_000 }, mutations: { retry: false } } }));
  const [router] = useState(makeRouter);
  return (
    <StrictMode>
      <AppContext.Provider value={ctx}>
        <QueryClientProvider client={qc}>
          <ToastProvider>
            <RouterProvider router={router} />
          </ToastProvider>
        </QueryClientProvider>
      </AppContext.Provider>
    </StrictMode>
  );
}

async function boot() {
  root.render(
    <Centered>
      <Spinner label="Loading" />
    </Centered>,
  );
  const res = await fetch(BASE_PATH + "/config.json", { cache: "no-store" });
  if (!res.ok) throw new Error(`could not load the portal configuration (${res.status})`);
  const config = (await res.json()) as PortalConfig;
  const env = { fetch: window.fetch.bind(window), storage: sessionStorage, navigate: (u: string) => location.assign(u), origin: location.origin, basePath: BASE_PATH };

  if (config.auth === "dev") {
    const auth = new DevAuth(env);
    const ctx = { config, auth, ep: endpoints(createApiClient({ auth })) };
    const render = () => root.render(auth.current() ? <App ctx={ctx} /> : <DevSignIn auth={auth} onDone={render} />);
    render();
    return;
  }

  if (!config.issuer || !config.client_id) {
    root.render(<Failure title="Sign-in is not configured" detail="Set MATURA_ISSUER (and MATURA_PORTAL_CLIENT_ID) on maturad, then reload." />);
    return;
  }
  const auth = new OidcAuth(config, env);
  if (location.pathname === BASE_PATH + "/callback") {
    const next = await auth.handleCallback(location.search);
    history.replaceState(null, "", next); // the code and state leave the address bar and history
  } else {
    await auth.login(location.pathname + location.search + location.hash);
  }
  root.render(<App ctx={{ config, auth, ep: endpoints(createApiClient({ auth })) }} />);
}

boot().catch((err: unknown) => {
  if (err instanceof RedirectingError) {
    root.render(
      <Centered>
        <Spinner label="Signing in" />
        Signing you in…
      </Centered>,
    );
    return;
  }
  root.render(<Failure title="Couldn't start the portal" detail={err instanceof Error ? err.message : String(err)} />);
});
