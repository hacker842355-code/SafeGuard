function parseWindowsListenerJson(output) {
  const parsed = output.trim() ? JSON.parse(output) : [];
  const rows = Array.isArray(parsed) ? parsed : [parsed];

  return rows.filter((row) =>
    row && (row.Protocol === 'TCP' || row.Protocol === 'UDP') &&
    Number.isInteger(Number(row.LocalPort)) && Number(row.LocalPort) > 0 && Number(row.LocalPort) <= 65535
  ).map((row) => ({
    Protocol: row.Protocol,
    LocalAddress: String(row.LocalAddress || ''),
    LocalPort: Number(row.LocalPort),
    OwningProcess: Number(row.OwningProcess) || 0,
  }));
}

module.exports = { parseWindowsListenerJson };
