const chart = document.querySelector('#interface-history-chart');
const data = document.querySelector('#interface-history-data');

if (chart && data) {
  const { since, until, points } = JSON.parse(data.textContent);
  const start = Date.parse(since);
  const end = Date.parse(until);
  const ctx = chart.getContext('2d');
  const series = [
    { field: 'rx_bps', label: '.network-rx', dashed: false },
    { field: 'tx_bps', label: '.network-tx', dashed: true },
  ];
  const maximum = Math.max(1, ...points.flatMap(({ rx_bps, tx_bps }) => [rx_bps, tx_bps])) / 1e6;
  const number = new Intl.NumberFormat('ru-RU', { maximumSignificantDigits: 3 });
  const time = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });

  function draw() {
    const { width, height } = chart.getBoundingClientRect();
    if (!ctx || !width || !height) return;
    const scale = window.devicePixelRatio || 1;
    chart.width = Math.round(width * scale);
    chart.height = Math.round(height * scale);
    ctx.scale(scale, scale);
    ctx.font = '12px system-ui, sans-serif';
    const top = 16;
    const left = 14 + ctx.measureText(number.format(maximum)).width;
    const right = width - 12;
    const bottom = height - 26;
    const x = timestamp => left + ((timestamp - start) / (end - start)) * (right - left);
    ctx.fillStyle = getComputedStyle(chart).color;
    ctx.strokeStyle = 'rgba(120, 128, 140, 0.35)';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 4; i++) {
      const y = bottom - (i / 4) * (bottom - top);
      ctx.fillText(number.format(maximum * i / 4), left - 6, y);
      ctx.beginPath();
      ctx.moveTo(left, y);
      ctx.lineTo(right, y);
      ctx.stroke();
    }
    ctx.textAlign = 'left';
    ctx.fillText(time.format(start), left, bottom + 16);
    ctx.textAlign = 'center';
    ctx.fillText(time.format((start + end) / 2), (left + right) / 2, bottom + 16);
    ctx.textAlign = 'right';
    ctx.fillText(time.format(end), right, bottom + 16);

    ctx.save();
    ctx.beginPath();
    ctx.rect(left, top - 2, right - left, bottom - top + 4);
    ctx.clip();
    for (const { field, label, dashed } of series) {
      ctx.strokeStyle = getComputedStyle(document.querySelector(label)).color;
      ctx.lineWidth = 2;
      ctx.setLineDash(dashed ? [5, 3] : []);
      ctx.beginPath();
      for (const point of points) {
        if (point[field] === null) continue;
        const timestamp = Date.parse(point.observed_at);
        const y = bottom - (point[field] / 1e6 / maximum) * (bottom - top);
        ctx.moveTo(x(timestamp - point.interval_seconds * 1000), y);
        ctx.lineTo(x(timestamp), y);
      }
      ctx.stroke();
    }
    ctx.restore();
  }

  new ResizeObserver(draw).observe(chart);
}
