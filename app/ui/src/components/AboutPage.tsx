import { useEffect, useState } from "react";
import { api, errorText, type About } from "../api";
import { Markdown } from "./Markdown";

/** M9: version, licence, the privacy notice and the third-party notices. */
export function AboutPage({ onBack }: { onBack: () => void }) {
  const [about, setAbout] = useState<About | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [licence, setLicence] = useState(false);
  const [notices, setNotices] = useState<string | null>(null);

  useEffect(() => {
    api.about().then(setAbout).catch((e) => setError(errorText(e)));
  }, []);

  const showNotices = async () => {
    if (notices !== null) return setNotices(null);
    try {
      setNotices(await api.notices());
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <div className="page">
      <div className="page-inner">
        <div className="page-head">
          <h1>About UNTRACE</h1>
          <button className="btn" onClick={onBack}>
            Back
          </button>
        </div>
        {error && <p className="small danger">{error}</p>}
        <section className="card">
          <dl className="facts-grid">
            <dt>Version</dt>
            <dd>{about?.version ?? "—"}</dd>
            <dt>Browser engine</dt>
            <dd>WebView2 Runtime {about?.runtimeVersion ?? "—"} (Microsoft, updated by Windows)</dd>
            <dt>Licence</dt>
            <dd>
              Mozilla Public License 2.0 ({about?.licence ?? "MPL-2.0"}).{" "}
              <button className="btn small-btn" onClick={() => setLicence((v) => !v)}>
                {licence ? "Hide licence" : "Show licence"}
              </button>
            </dd>
          </dl>
          {licence && about && <pre className="notices">{about.licenceText}</pre>}
        </section>
        <section className="card">
          <h2>Privacy notice</h2>
          {about ? <Markdown text={about.privacy} skipTitle /> : <p className="muted">Reading…</p>}
        </section>
        <section className="card">
          <div className="page-head">
            <h2>Third-party software</h2>
            <button className="btn small-btn" onClick={showNotices}>
              {notices !== null ? "Hide notices" : "Show notices"}
            </button>
          </div>
          <p className="muted small">
            UNTRACE is built with open-source components, each under its own licence. The block lists keep their own licences too;
            Settings names each list's source and licence.
          </p>
          {notices !== null && <pre className="notices">{notices}</pre>}
        </section>
      </div>
    </div>
  );
}
