import { api, type Snapshot } from "../api";
import { tabTitle } from "../util";
import { Close, Globe, Plus, Temporary } from "./Icons";

type Props = { snap: Snapshot; onNewTab: () => void; onNewTemporary: () => void };

export function TabStrip({ snap, onNewTab, onNewTemporary }: Props) {
  return (
    <div className="tabbar" role="tablist" aria-label="Tabs">
      {snap.tabs.map((t) => {
        const active = t.id === snap.active;
        const title = tabTitle(t);
        const label =
          (t.temporary ? `${title} (temporary)` : title) + (t.sleeping ? " (sleeping: wakes when you open it)" : "");
        return (
          <div
            key={t.id}
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            className={`tab${active ? " active" : ""}${t.crashed ? " crashed" : ""}${t.temporary ? " temporary" : ""}${t.sleeping ? " sleeping" : ""}`}
            title={label}
            onMouseDown={(e) => {
              if (e.button === 1) {
                e.preventDefault();
                api.tabClose(t.id);
              }
            }}
            onClick={() => api.tabActivate(t.id)}
          >
            <span className="tab-icon">
              {t.loading ? (
                <span className="spinner" aria-label="Loading" />
              ) : t.temporary ? (
                <Temporary size={14} />
              ) : t.favicon ? (
                <img src={t.favicon} alt="" width={16} height={16} />
              ) : (
                <Globe size={14} />
              )}
            </span>
            <span className="tab-title">{title}</span>
            <button
              className="tab-close"
              aria-label={`Close ${label}`}
              onClick={(e) => {
                e.stopPropagation();
                api.tabClose(t.id);
              }}
            >
              <Close size={12} />
            </button>
          </div>
        );
      })}
      <button className="icon-btn new-tab" aria-label="New tab (Ctrl+T)" title="New tab (Ctrl+T)" onClick={onNewTab}>
        <Plus />
      </button>
      <button
        className="icon-btn new-tab"
        aria-label="New temporary tab (Ctrl+Shift+N)"
        title="New temporary tab (Ctrl+Shift+N): nothing is kept after the last temporary tab closes"
        onClick={onNewTemporary}
      >
        <Temporary />
      </button>
    </div>
  );
}
