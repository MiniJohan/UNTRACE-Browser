// 16 px stroke icons, drawn for UNTRACE. They inherit `currentColor`.
type P = { size?: number };

const Svg = ({ size = 16, children }: P & { children: React.ReactNode }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
    {children}
  </svg>
);

export const Back = (p: P) => <Svg {...p}><path d="M10 3.5 5.5 8l4.5 4.5" /></Svg>;
export const Forward = (p: P) => <Svg {...p}><path d="M6 3.5 10.5 8 6 12.5" /></Svg>;
export const Reload = (p: P) => (
  <Svg {...p}><path d="M13 8a5 5 0 1 1-1.5-3.6" /><path d="M13 3v3h-3" /></Svg>
);
export const Close = (p: P) => <Svg {...p}><path d="M4.5 4.5l7 7M11.5 4.5l-7 7" /></Svg>;
export const Plus = (p: P) => <Svg {...p}><path d="M8 3.5v9M3.5 8h9" /></Svg>;
export const Gear = (p: P) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="2" />
    <path d="M8 1.75v1.5M8 12.75v1.5M14.25 8h-1.5M3.25 8h-1.5M12.4 3.6l-1.06 1.06M4.66 11.34 3.6 12.4M12.4 12.4l-1.06-1.06M4.66 4.66 3.6 3.6" />
  </Svg>
);
export const Pulse = (p: P) => <Svg {...p}><path d="M1.75 8h3l1.75-4 3 8 1.75-4h3" /></Svg>;
export const Info = (p: P) => (
  <Svg {...p}><circle cx="8" cy="8" r="6.25" /><path d="M8 7.25v3.5M8 5.1v.01" /></Svg>
);
export const Globe = (p: P) => (
  <Svg {...p}><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c1.8 1.7 2.6 3.7 2.6 6S9.8 12.3 8 14C6.2 12.3 5.4 10.3 5.4 8S6.2 3.7 8 2Z" /></Svg>
);
export const Check = (p: P) => <Svg {...p}><path d="m3.5 8.5 3 3 6-7" /></Svg>;
export const Cross = Close;
export const Question = (p: P) => (
  <Svg {...p}><circle cx="8" cy="8" r="6.25" /><path d="M6.4 6.3a1.7 1.7 0 0 1 3.2.8c0 1.2-1.6 1.4-1.6 2.4M8 11.4v.01" /></Svg>
);
export const Download = (p: P) => (
  <Svg {...p}><path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.25h10" /></Svg>
);
/** A temporary tab: dashed outline. */
export const Temporary = (p: P) => (
  <Svg {...p}><circle cx="8" cy="8" r="5.75" strokeDasharray="2.2 1.9" /><path d="M8 5.6v4.8M5.6 8h4.8" /></Svg>
);
export const Star = ({ filled, ...p }: P & { filled?: boolean }) => (
  <Svg {...p}>
    <path
      d="M8 2.2l1.75 3.6 3.95.55-2.87 2.77.69 3.93L8 11.2l-3.52 1.85.69-3.93L2.3 6.35l3.95-.55Z"
      fill={filled ? "currentColor" : "none"}
    />
  </Svg>
);
export const BookmarkList = (p: P) => (
  <Svg {...p}><path d="M4 2.5h8v11L8 10.75 4 13.5Z" /></Svg>
);
export const Folder = (p: P) => (
  <Svg {...p}><path d="M2 4.25c0-.7.55-1.25 1.25-1.25h3l1.5 1.75h5c.7 0 1.25.55 1.25 1.25v5.75c0 .7-.55 1.25-1.25 1.25h-9.5C2.55 13 2 12.45 2 11.75Z" /></Svg>
);
export const Chevron = ({ open, ...p }: P & { open?: boolean }) => (
  <Svg {...p}><path d={open ? "M4 6l4 4 4-4" : "M6 4l4 4-4 4"} /></Svg>
);
export const Edit = (p: P) => (
  <Svg {...p}><path d="M10.5 2.75l2.75 2.75L6 12.75H3.25V10Z" /></Svg>
);
