import { NavLink, Outlet } from "react-router-dom";
import { api } from "@/shared/api";
import { useHealth } from "@/shared/api/queries";
import { IconBook, IconGithub, IconHome, IconScan } from "./icons";

const REPO = "https://github.com/ulisespignatelli/cryptoinv";

export function Layout() {
  const health = useHealth();
  return (
    <>
      <div className="shell">
        <aside className="side">
          <NavLink to="/" className="brand" end>
            <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" />
            <span>
              <b>cryptoinv</b>
              <small>preparación post-cuántica</small>
            </span>
          </NavLink>
          <nav className="nav" aria-label="Principal">
            <NavLink to="/" end>
              <IconHome /> Vista general
            </NavLink>
            <NavLink to="/scans">
              <IconScan /> Escaneos
            </NavLink>
            <NavLink to="/catalog">
              <IconBook /> Catálogo
            </NavLink>
            <a href={REPO} target="_blank" rel="noreferrer">
              <IconGithub /> Código
            </a>
          </nav>
          <div className="side__foot">
            {health.data ? (
              <>
                <b>{api.mode === "demo" ? "Modo demo" : "Servidor local"}</b> · {/^\d/.test(health.data.version) ? "v" : ""}{health.data.version}
              </>
            ) : health.isError ? (
              <span>Sin conexión con el servidor</span>
            ) : (
              "…"
            )}
          </div>
        </aside>
        <main className="main">
          {api.mode === "demo" && (
            <div className="demo-banner">
              <span>
                Demo con escaneos reales de proyectos de código abierto. Para escanear tus sistemas, instalá cryptoinv y corré <code>cryptoinv serve</code>.
              </span>
              <a href={REPO}>Ver en GitHub →</a>
            </div>
          )}
          <Outlet />
        </main>
      </div>
    </>
  );
}
