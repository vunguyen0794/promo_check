module.exports = (req, res) => {
  const targetUrl = `http://222.255.184.49${req.url || '/'}`;
  res.writeHead(307, {
    'Location': targetUrl,
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end(`Redirecting to ${targetUrl}`);
};
