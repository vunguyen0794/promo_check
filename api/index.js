module.exports = (req, res) => {
  const targetUrl = `https://webmien.duckdns.org${req.url || '/'}`;
  res.writeHead(301, {
    'Location': targetUrl,
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end(`Redirecting to ${targetUrl}`);
};
