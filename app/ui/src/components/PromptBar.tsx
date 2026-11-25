import { useState } from "react";
import { api, type PromptInfo, type TabInfo } from "../api";
import { formatBytes } from "../util";
import { Close } from "./Icons";

/**
 * Questions from the active page (permissions, other applications, downloads) and notices about
 * things UNTRACE refused. Sits above the page and pushes it down — it never covers web content.
 */
export function PromptBar({ tab }: { tab: TabInfo }) {
  const prompt = tab.prompts[0];
  if (!prompt && !tab.notice) return null;
  return (
    <div className="prompt-bar" role="region" aria-label="Questions from this page">
      {prompt ? <PromptRow key={prompt.id} prompt={prompt} more={tab.prompts.length - 1} /> : null}
      {!prompt && tab.notice && (
        <div className="prompt-row">
          <span className="prompt-text">{tab.notice}</span>
          <button className="icon-btn" aria-label="Dismiss" onClick={() => api.dismissNotice(tab.id)}>
            <Close size={14} />
          </button>
        </div>
      )}
    </div>
  );
}

function PromptRow({ prompt, more }: { prompt: PromptInfo; more: number }) {
  const [remember, setRemember] = useState(false);
  const answer = (allow: boolean) => api.respond(prompt.id, allow, remember).catch(() => {});
  const d = prompt.detail;
  const site = <span className="mono">{prompt.origin}</span>;
  const extra = more > 0 ? <span className="muted small">+{more} more</span> : null;

  if (d.type === "permission") {
    return (
      <div className="prompt-row">
        <span className="prompt-text">
          {site} wants to {d.phrase}.
        </span>
        <label className="check-label">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          Remember for this site
        </label>
        {extra}
        <button className="btn" onClick={() => answer(false)}>Block</button>
        <button className="btn primary" onClick={() => answer(true)}>Allow</button>
      </div>
    );
  }

  if (d.type === "external_app") {
    return (
      <div className="prompt-row">
        <span className="prompt-text">
          {site} wants to open another application <span className="mono">({d.scheme}:)</span>
          <span className="prompt-target mono">{d.target}</span>
        </span>
        {extra}
        <button className="btn primary" onClick={() => answer(false)}>Don't open</button>
        <button className="btn" onClick={() => answer(true)}>Open</button>
      </div>
    );
  }

  const risky = d.risk === "runs_code";
  return (
    <div className={`prompt-row${risky ? " risky" : ""}`}>
      <span className="prompt-text">
        Save <strong>{d.file_name}</strong>
        {d.size ? ` (${formatBytes(d.size)})` : ""} from {site}?
        {risky && (
          <span className="prompt-warning">
            This kind of file can run programs on your computer. Only save it if you trust the site.
          </span>
        )}
      </span>
      {extra}
      <button className={`btn${risky ? " primary" : ""}`} onClick={() => answer(false)}>Cancel</button>
      <button className={`btn${risky ? "" : " primary"}`} onClick={() => answer(true)}>Save…</button>
    </div>
  );
}
