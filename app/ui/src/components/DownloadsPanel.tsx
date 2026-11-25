import { api, type DownloadInfo } from "../api";
import { formatBytes } from "../util";
import { Close } from "./Icons";

function stateText(d: DownloadInfo): string {
  if (d.state === "completed") return d.total ? `Done · ${formatBytes(d.total)}` : "Done";
  if (d.state === "interrupted") return "Failed or cancelled";
  if (d.total) return `${Math.floor((d.received / d.total) * 100)} % of ${formatBytes(d.total)}`;
  return `${formatBytes(d.received)} so far`;
}

export function DownloadsPanel({ downloads, onClose }: { downloads: DownloadInfo[]; onClose: () => void }) {
  return (
    <aside className="side-panel" aria-label="Downloads">
      <header className="panel-head">
        <h2>Downloads</h2>
        <button className="icon-btn" aria-label="Close panel" onClick={onClose}>
          <Close />
        </button>
      </header>
      {downloads.length === 0 && <p className="muted">No downloads in this session.</p>}
      <ul className="downloads">
        {[...downloads].reverse().map((d) => (
          <li key={d.id} className="download">
            <div className="download-name" title={d.path}>
              {d.fileName}
              {d.risk === "runs_code" && <span className="tag danger">can run code</span>}
            </div>
            <div className="muted small">{stateText(d)}</div>
            {d.state === "in_progress" && d.total ? (
              <div className="progress"><span style={{ width: `${Math.min(100, (d.received / d.total) * 100)}%` }} /></div>
            ) : null}
            <div className="download-actions">
              {d.state === "in_progress" && <button className="btn" onClick={() => api.cancelDownload(d.id)}>Cancel</button>}
              {d.state === "completed" && <button className="btn" onClick={() => api.showDownload(d.id).catch(() => {})}>Show in folder</button>}
            </div>
          </li>
        ))}
      </ul>
      {downloads.some((d) => d.state !== "in_progress") && (
        <button className="btn" onClick={() => api.clearDownloads()}>Clear list</button>
      )}
      <p className="muted small">
        The list is kept only until UNTRACE closes; saved files stay where you put them. Windows marks files from
        internet sites as downloaded from the internet, with the address they came from, and checks them when you open
        them. Files from this computer or your local network are not marked.
      </p>
    </aside>
  );
}
