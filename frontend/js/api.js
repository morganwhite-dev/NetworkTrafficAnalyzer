// REST helpers. The session cookie (HttpOnly) rides along automatically;
// state-changing calls add X-NTA-Request so cross-site pages can't forge them.

async function handle(res) {
  if (res.ok) {
    const type = res.headers.get("content-type") || "";
    return type.includes("json") ? res.json() : res;
  }
  let detail = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    if (body && body.detail) detail = String(body.detail);
  } catch {
    /* not JSON */
  }
  if (res.status === 401)
    detail = "Session expired. Open the link printed in the terminal again.";
  throw new Error(detail);
}

export async function get(path) {
  return handle(await fetch(path, { credentials: "same-origin" }));
}

export async function post(path, body) {
  return handle(
    await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-nta-request": "1" },
      body: JSON.stringify(body ?? {}),
    }),
  );
}

export async function uploadPcap(file) {
  return handle(
    await fetch("/api/pcap", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/octet-stream",
        "x-nta-request": "1",
        "x-nta-filename": encodeURIComponent(file.name).slice(0, 120),
      },
      body: file,
    }),
  );
}
