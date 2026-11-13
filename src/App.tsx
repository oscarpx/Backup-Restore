import { useState } from 'react';
import { TopBar, WorkspaceView } from './components/TopBar';
import { WpAdminSimulator } from './components/WpAdminSimulator';
import { SourceCodeViewer } from './components/SourceCodeViewer';
import { ArchitectureOverview } from './components/ArchitectureOverview';
import { BackupArchiveItem, INITIAL_BACKUPS } from './data/simulatedSite';
import { PLUGIN_FILES } from './lib/pluginFiles';
import { buildZipArchive } from './lib/zipBuilder';

export default function App() {
  const [activeView, setActiveView] = useState<WorkspaceView>('simulator');
  const [backups, setBackups] = useState<BackupArchiveItem[]>(INITIAL_BACKUPS);
  const [downloadMessage, setDownloadMessage] = useState<string | null>(null);

  function handleDownloadPluginZip() {
    const zipBytes = buildZipArchive(
      PLUGIN_FILES.map((file) => ({
        path: `oscarpx-backup-restore/${file.path}`,
        content: file.content,
      })),
    );
    const blob = new Blob([new Uint8Array(zipBytes).buffer], {
      type: 'application/zip',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'oscarpx-backup-restore.zip';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);

    setDownloadMessage(
      'Paquete oscarpx-backup-restore.zip generado. Listo para subir en WordPress Admin -> Plugins -> Añadir nuevo.',
    );
    window.setTimeout(() => setDownloadMessage(null), 5000);
  }

  function handleBackupCreated(item: BackupArchiveItem) {
    setBackups((prev) => [item, ...prev]);
  }

  function handleBackupDeleted(filename: string) {
    setBackups((prev) => prev.filter((b) => b.filename !== filename));
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#f0f0f1] text-[#1d2327]">
      <TopBar
        activeView={activeView}
        onSelectView={setActiveView}
        onDownloadZip={handleDownloadPluginZip}
      />

      {downloadMessage && (
        <div
          role="status"
          className="bg-white border-b border-slate-200 px-6 py-2.5 text-xs font-medium text-[#15803d] text-center"
        >
          {downloadMessage}
        </div>
      )}

      <div className="flex-1">
        {activeView === 'simulator' && (
          <WpAdminSimulator
            backups={backups}
            onBackupCreated={handleBackupCreated}
            onBackupDeleted={handleBackupDeleted}
          />
        )}
        {activeView === 'code' && (
          <SourceCodeViewer onDownloadZip={handleDownloadPluginZip} />
        )}
        {activeView === 'architecture' && <ArchitectureOverview />}
      </div>

      <footer className="border-t border-slate-200 bg-white px-6 py-4 text-xs text-slate-500">
        <div className="max-w-[1380px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>OscarPx Backup &amp; Restore v1.0.0 · Desarrollado por OscarPx</span>
          <a
            href="https://oscarpx.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[#2271b1] hover:underline"
          >
            oscarpx.com
          </a>
        </div>
      </footer>
    </div>
  );
}
