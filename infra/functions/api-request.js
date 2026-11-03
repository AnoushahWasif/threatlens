// CloudFront Function (cloudfront-js-2.0), viewer request on /api/*. The browser calls the
// API on the site's own origin; API Gateway's routes have no /api prefix.
function handler(event) {
  var request = event.request;
  var rest = request.uri.slice("/api".length);
  request.uri = rest === "" ? "/" : rest;
  return request;
}
