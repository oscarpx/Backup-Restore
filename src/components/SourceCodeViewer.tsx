import { useState } from 'react';
import { Check, Copy, Download, FileCode2 } from 'lucide-react';
import { PLUGIN_FILES } from '../lib/pluginFiles';

interface SourceCodeViewerProps {
  onDownloadZip: () => void;
}

export function SourceCodeViewer({ onDownloadZip }: SourceCodeViewerProps) {
  const [selectedPath, setSelectedPath] = useState<string>(PLUGIN_FILES[0].path);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  const activeFile =
    PLUGIN_FILES.find((f) => f.path === selectedPath) ?? PLUGIN_FILES[0];
  const lineCount = activeFile.content.split('\n').length;

  function handleCopy() {
    navigator.clipboard.writeText(activeFile.content).then(() => {
      setCopiedPath(activeFile.path);
      window.setTimeout(() => setCopiedPath(null), 1800);
    });
  }

  return (
    <div className="max-w-[1380px] mx-auto px-4 sm:px-6 py-6">
      <div className="bg-white border border-slate-200 rounded overflow-hidden flex flex-col lg:flex-row">
        {/* Árbol de archivos */}
        <aside
          aria-label="Archivos del plugin"
          className="lg:w-[325px] shrink-0 border-b lg:border-b-0 lg:border-r border-slate-200 bg-slate-50"
        >
          <div className="px-4 py-3.5 border-b border-slate-200 flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-slate-700 font-mono">
              oscarpx-backup-restore/
            </span>
            <span className="text-xs text-slate-500 tabular-nums">
              {PLUGIN_FILES.length} archivos
            </span>
          </div>
          <nav className="p-2 flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible">
            {PLUGIN_FILES.map((file) => {
              const isSelected = file.path === activeFile.path;
              return (
                <button
                  key={file.path}
                  type="button"
                  onClick={() => setSelectedPath(file.path)}
                  className={`text-left px-3 py-2 rounded text-xs font-mono flex items-center gap-2 whitespace-nowrap lg:whitespace-normal transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-[#2271b1] text-white font-semibold'
                      : 'text-slate-700 hover:bg-slate-200/70'
                  }`}
                >
                  <FileCode2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                  <span className="truncate">{file.path}</span>
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Visor de código */}
        <div className="flex-1 min-w-0 flex flex-col">
          <div className="px-5 py-4 border-b border-slate-200 bg-white flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 font-mono">
                <span>{activeFile.path}</span>
                <span className="text-slate-400">·</span>
                <span className="text-xs font-normal text-slate-500 tabular-nums">
                  {lineCount} líneas
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1">{activeFile.summary}</p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                {copiedPath === activeFile.path ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#16a34a]" aria-hidden="true" />
                    <span>Copiado</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Copiar archivo</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={onDownloadZip}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-[#2271b1] hover:bg-[#135e96] rounded transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Descargar .zip</span>
              </button>
            </div>
          </div>

          <div className="bg-[#0f172a] text-slate-100 overflow-x-auto max-h-[680px] overflow-y-auto">
            <pre className="p-5 text-[12.5px] leading-relaxed font-mono m-0">
              <code>{activeFile.content}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
