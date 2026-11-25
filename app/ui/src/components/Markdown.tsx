import type { ReactNode } from "react";

/**
 * Renders the small Markdown subset UNTRACE's own documents use (PRIVACY.md): headings,
 * paragraphs, bulleted lists one level deep, continuation lines, **bold** and `code`.
 * It builds React elements only; no HTML from the text is ever injected.
 */
function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    out.push(t.startsWith("**") ? <strong key={k++}>{t.slice(2, -2)}</strong> : <code key={k++}>{t.slice(1, -1)}</code>);
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

type Item = { text: string; children: string[]; after: string };
type Block =
  | { kind: "h"; level: number; text: string }
  | { kind: "p"; text: string }
  | { kind: "ul"; items: Item[] };

function parse(src: string): Block[] {
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: Item[] | null = null;
  const flushPara = () => {
    if (para.length) blocks.push({ kind: "p", text: para.join(" ") });
    para = [];
  };
  const flushList = () => {
    if (list) blocks.push({ kind: "ul", items: list });
    list = null;
  };
  for (const raw of src.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trimEnd();
    const h = /^(#{1,3}) (.*)$/.exec(line);
    const top = /^- (.*)$/.exec(line);
    const sub = /^ {2,}- (.*)$/.exec(line);
    if (!line.trim()) {
      flushPara();
      flushList();
    } else if (h) {
      flushPara();
      flushList();
      blocks.push({ kind: "h", level: h[1].length, text: h[2] });
    } else if (top) {
      flushPara();
      list ??= [];
      list.push({ text: top[1], children: [], after: "" });
    } else if (sub && list && list.length) {
      list[list.length - 1].children.push(sub[1]);
    } else if (list && list.length && /^ {2,}/.test(line)) {
      // A continuation line of the last sub-item (indented deeper), of the item itself, or a
      // closing sentence of the item after its sub-items.
      const it = list[list.length - 1];
      if (it.children.length && /^ {4,}/.test(line)) it.children[it.children.length - 1] += " " + line.trim();
      else if (it.children.length) it.after = (it.after + " " + line.trim()).trim();
      else it.text += " " + line.trim();
    } else {
      flushList();
      para.push(line.trim());
    }
  }
  flushPara();
  flushList();
  return blocks;
}

export function Markdown({ text, skipTitle }: { text: string; skipTitle?: boolean }) {
  const blocks = parse(text).filter((b, i) => !(skipTitle && i === 0 && b.kind === "h"));
  return (
    <div className="md">
      {blocks.map((b, i) =>
        b.kind === "h" ? (
          b.level <= 2 ? <h3 key={i}>{inline(b.text)}</h3> : <h4 key={i}>{inline(b.text)}</h4>
        ) : b.kind === "p" ? (
          <p key={i}>{inline(b.text)}</p>
        ) : (
          <ul key={i}>
            {b.items.map((it, j) => (
              <li key={j}>
                {inline(it.text)}
                {it.children.length > 0 && (
                  <ul>
                    {it.children.map((c, n) => (
                      <li key={n}>{inline(c)}</li>
                    ))}
                  </ul>
                )}
                {it.after && <div>{inline(it.after)}</div>}
              </li>
            ))}
          </ul>
        ),
      )}
    </div>
  );
}
