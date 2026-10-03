export function formatTimestamp(ts?: string | null): string {
  if (!ts) return "N/A";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toISOString().replace("T", " ").replace("Z", " UTC");
  } catch {
    return ts;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatProtocol(protocol?: string): string {
  if (!protocol) return "UNKNOWN";
  return protocol.toUpperCase();
}

export function formatFrameNumbers(frames?: number[] | null): string {
  if (!frames || frames.length === 0) return "None";
  if (frames.length === 1) return `Frame #${frames[0]}`;
  if (frames.length <= 5) return `Frames #${frames.join(", #")}`;
  return `Frames #${frames.slice(0, 4).join(", #")} (+${frames.length - 4} more)`;
}

export function formatAddress(ip: string, port: number): string {
  return `${ip}:${port}`;
}
