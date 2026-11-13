import { Download } from 'lucide-react';

export type WorkspaceView = 'simulator' | 'code' | 'architecture';

interface TopBarProps {
  activeView: WorkspaceView;
  onSelectView: (view: WorkspaceView) => void;
  onDownloadZip: () => void;
}

export function TopBar({ activeView, onSelectView, onDownloadZip }: TopBarProps) {
  const navItems: { id: WorkspaceView; label: string }[] = [
    { id: 'simulator', label: 'Simulador WP-Admin' },
    { id: 'code', label: 'Código Fuente' },
    { id: 'architecture', label: 'Arquitectura' },
  ];

  return (
    <header className="bg-white border-b border-slate-200 px-4 sm:px-6 py-3.5">
      <div className="max-w-[1380px] mx-auto flex items-center justify-between gap-3 md:gap-8">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            onSelectView('simulator');
          }}
          className="text-base sm:text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#2271b1]"
        >
          OscarPx Backup &amp; Restore
        </a>

        <nav
          aria-label="Navegación principal"
          className="hidden md:flex items-center gap-6 text-sm font-medium"
        >
          {navItems.map((item) => {
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectView(item.id)}
                className={`py-1.5 whitespace-nowrap shrink-0 border-b-2 transition-colors duration-150 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#2271b1] ${
                  isActive
                    ? 'border-[#2271b1] text-[#2271b1] font-semibold'
                    : 'border-transparent text-slate-600 hover:text-slate-900'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={onDownloadZip}
            className="inline-flex items-center gap-1.5 sm:gap-2 px-3 py-2 sm:px-4 text-xs font-semibold text-white bg-[#2271b1] hover:bg-[#135e96] rounded transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2271b1]"
          >
            <Download className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span className="hidden sm:inline">Descargar Plugin .zip</span>
            <span className="sm:hidden">Plugin .zip</span>
          </button>
        </div>
      </div>

      {/* Navegación móvil compacta */}
      <nav
        aria-label="Navegación móvil"
        className="flex md:hidden items-center gap-4 mt-3 pt-2.5 border-t border-slate-100 overflow-x-auto text-xs font-medium"
      >
        {navItems.map((item) => {
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectView(item.id)}
              className={`py-1.5 whitespace-nowrap shrink-0 border-b-2 transition-colors ${
                isActive
                  ? 'border-[#2271b1] text-[#2271b1] font-semibold'
                  : 'border-transparent text-slate-600'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
