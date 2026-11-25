import { useLayoutEffect, useRef } from "react";
import { api, type TabInfo } from "../api";
import { InterstitialView } from "./InterstitialView";

/**
 * Reserves the area where the native page view is placed. The UI never draws over web content
 * (the page view is a separate window); it only draws here when the host has hidden the page
 * view — for UNTRACE's own error panels, or when the engine is unavailable.
 */
export function ContentSlot({ engineError, tab }: { engineError: string | null; tab: TabInfo | undefined }) {
  const ref = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    let raf = 0;
    const send = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const r = el.getBoundingClientRect();
        api.setContentBounds({ x: r.left, y: r.top, width: r.width, height: r.height, visible: true }).catch(() => {});
      });
    };
    const ro = new ResizeObserver(send);
    ro.observe(el);
    window.addEventListener("resize", send);
    send();
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", send);
      cancelAnimationFrame(raf);
      api.setContentBounds({ x: 0, y: 0, width: 0, height: 0, visible: false }).catch(() => {});
    };
  }, []);

  return (
    <div className="content-slot" ref={ref}>
      {engineError ? (
        <div className="interstitial" role="alert">
          <h2>The browser engine is not available</h2>
          <p>{engineError}</p>
        </div>
      ) : tab?.interstitial ? (
        <InterstitialView tabId={tab.id} value={tab.interstitial} />
      ) : null}
    </div>
  );
}
