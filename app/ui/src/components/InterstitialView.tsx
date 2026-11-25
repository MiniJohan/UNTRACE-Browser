import { api, type Interstitial } from "../api";
import { formatDate } from "../util";

/**
 * UNTRACE's own page for failed or refused navigations. Drawn by the trusted UI in the content
 * area while the page view is hidden, so its buttons never run inside web content.
 */
export function InterstitialView({ tabId, value }: { tabId: number; value: Interstitial }) {
  const act = (a: "back" | "retry" | "continue_http" | "continue_threat") =>
    api.interstitialAction(tabId, a).catch(() => {});

  if (value.kind === "threat") {
    const phishing = value.list === "phishing";
    return (
      <div className="interstitial" role="alert">
        <h2 className="danger">{phishing ? "This site is reported for phishing" : "This site is reported for spreading malware"}</h2>
        <p>
          <span className="mono">{value.host}</span> is on the {value.list_title} list. UNTRACE stopped before
          contacting it.
        </p>
        <p className="muted">
          {phishing
            ? "Sites on this list imitate other sites to steal passwords or payment details. Do not sign in or enter card details here."
            : "Sites on this list have recently been used to spread malicious software. Opening it could infect this computer."}
        </p>
        <div className="actions">
          <button className="btn primary" onClick={() => act("back")}>Go back</button>
          <button className="btn" onClick={() => act("continue_threat")}>Continue anyway</button>
        </div>
        <p className="muted small">
          Continuing allows {value.host} until UNTRACE closes; it is not remembered. Lists can be wrong: if this site is
          listed by mistake, its maintainers take reports at <span className="mono">{value.list_homepage}</span>.
        </p>
      </div>
    );
  }

  if (value.kind === "https_unavailable") {
    return (
      <div className="interstitial" role="alert">
        <h2>This site has no secure connection</h2>
        <p>
          UNTRACE tried to open <span className="mono">{value.host}</span> over HTTPS and could not: {value.reason}
        </p>
        <p className="muted">
          If you continue, everything you send and receive on this site travels unencrypted and can be read or changed
          by others on the network.
        </p>
        <div className="actions">
          <button className="btn primary" onClick={() => act("back")}>Go back</button>
          <button className="btn" onClick={() => act("continue_http")}>Continue over HTTP</button>
        </div>
        <p className="muted small">Continuing allows plain HTTP for {value.host} until UNTRACE closes.</p>
      </div>
    );
  }

  if (value.kind === "certificate") {
    const c = value.certificate;
    return (
      <div className="interstitial" role="alert">
        <h2 className="danger">This connection is not secure</h2>
        <p>
          The certificate presented by <span className="mono">{value.host}</span> was rejected: {value.reason}
        </p>
        <p className="muted">
          Someone may be impersonating the site, or it is misconfigured. UNTRACE never continues past a certificate
          error.
        </p>
        {c && (
          <dl className="facts-grid compact">
            <dt>Issued to</dt><dd className="mono">{c.subject || "—"}</dd>
            <dt>Issued by</dt><dd className="mono">{c.issuer || "—"}</dd>
            <dt>Valid</dt><dd>{formatDate(c.validFrom)} – {formatDate(c.validTo)}</dd>
          </dl>
        )}
        <div className="actions">
          <button className="btn primary" onClick={() => act("back")}>Go back</button>
          <button className="btn" onClick={() => act("retry")}>Try again</button>
        </div>
      </div>
    );
  }

  return (
    <div className="interstitial" role="alert">
      <h2>Can't open this page</h2>
      <p>
        {value.host && <span className="mono">{value.host}</span>} {value.reason}
      </p>
      <div className="actions">
        <button className="btn primary" onClick={() => act("retry")}>Try again</button>
        <button className="btn" onClick={() => act("back")}>Go back</button>
      </div>
    </div>
  );
}
