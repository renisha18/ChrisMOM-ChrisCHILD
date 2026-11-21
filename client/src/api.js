// Small fetch wrapper: returns parsed JSON, throws Error with a friendly message.
export async function api(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
  } catch {
    throw new Error("Can't reach the server. Check your connection.");
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON response */
  }
  if (res.status === 401 && path !== "/login") {
    window.dispatchEvent(new Event("auth-expired")); // session ended: AuthProvider clears user
  }
  if (!res.ok) throw new Error(data?.error || "Something went wrong. Please try again.");
  return data;
}
