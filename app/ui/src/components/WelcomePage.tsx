/** M9: the one-screen welcome, shown once at the first start. No tour. */
export function WelcomePage({ onStart, onPrivacy }: { onStart: () => void; onPrivacy: () => void }) {
  return (
    <div className="page">
      <div className="page-inner welcome">
        <h1>Welcome to UNTRACE</h1>
        <p className="lead">A browser that blocks tracking and tells you plainly what it does and does not do.</p>
        <section className="card">
          <h2>What it does, from the start</h2>
          <ul className="welcome-list">
            <li>Blocks ads and trackers, and hides the space they leave.</li>
            <li>Warns you before malware and phishing sites, and opens sites over HTTPS only.</li>
            <li>Looks names up through its own network layer, encrypted where it can, and keeps WebRTC inside it.</li>
            <li>Keeps websites away from your router and other devices on your network.</li>
            <li>Deletes the cache when you close it. No account, no analytics: nothing about you is sent to UNTRACE's makers.</li>
          </ul>
        </section>
        <section className="card">
          <h2>What it does not do</h2>
          <ul className="welcome-list">
            <li>It is not a VPN: websites see your IP address.</li>
            <li>Websites can tell that it runs on Microsoft's WebView2 engine.</li>
            <li>The engine, a part of Windows, sends Microsoft the diagnostic data your Windows settings require.</li>
          </ul>
        </section>
        <p className="muted">
          Every protection is explained in Settings, with its limits, and can be changed there. Diagnostics shows what UNTRACE could
          verify.
        </p>
        <div className="inline-form">
          <button className="btn primary" onClick={onStart} autoFocus>
            Start browsing
          </button>
          <button className="btn" onClick={onPrivacy}>
            Read the privacy notice
          </button>
        </div>
      </div>
    </div>
  );
}
