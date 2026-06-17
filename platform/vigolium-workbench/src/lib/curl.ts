// Convert a raw HTTP request string into an equivalent `curl` command.
//
// The raw request looks like:
//   GET /path?q=1 HTTP/1.1
//   Host: example.com
//   User-Agent: ...
//
//   <optional body>
//
// `matchedAt` (a finding's matched URLs) is used only to recover the scheme
// (http vs https), which the raw request line never carries; defaults to https.

function shellQuote(value: string): string {
  // Wrap in single quotes, escaping any embedded single quotes the POSIX way.
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function rawRequestToCurl(rawRequest: string, matchedAt?: string[]): string {
  const normalized = rawRequest.replace(/\r\n/g, '\n');
  // Split head (request line + headers) from body at the first blank line.
  const sep = normalized.indexOf('\n\n');
  const head = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? '' : normalized.slice(sep + 2);

  const lines = head.split('\n');
  const requestLine = (lines.shift() ?? '').trim();
  const [method = 'GET', target = '/'] = requestLine.split(/\s+/);

  const headers: Array<[string, string]> = [];
  let host = '';
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (!name) continue;
    if (name.toLowerCase() === 'host') host = val;
    headers.push([name, val]);
  }

  // Build the absolute URL. If the request target is already absolute
  // (proxy-style), use it as-is; otherwise join scheme + host + target.
  let url: string;
  if (/^https?:\/\//i.test(target)) {
    url = target;
  } else {
    let scheme = 'https';
    const matched = matchedAt?.find((u) => /^https?:\/\//i.test(u));
    if (matched) {
      scheme = matched.toLowerCase().startsWith('http://') ? 'http' : 'https';
    } else if (!host) {
      scheme = 'http';
    }
    url = `${scheme}://${host}${target}`;
  }

  const parts: string[] = [`curl -i -s -k -X ${method} ${shellQuote(url)}`];
  for (const [name, val] of headers) {
    parts.push(`  -H ${shellQuote(`${name}: ${val}`)}`);
  }
  if (body.trim() !== '') {
    parts.push(`  --data-raw ${shellQuote(body)}`);
  }

  return parts.join(' \\\n');
}
