// CloudFront Function (cloudfront-js-2.0), viewer request. Maps clean URLs to the files a
// Next.js static export writes. Kept to ES5 so it runs on the Functions runtime as is.
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // Prefetch files (/a/b/__next.a.b.__PAGE__.txt) are served as they are: since Next 16.4.5
  // the export writes them under the names browsers request (decision 52).
  if (uri === "/") {
    request.uri = "/index.html";
  } else if (uri.charAt(uri.length - 1) === "/") {
    request.uri = uri.slice(0, -1) + ".html";
  } else if (uri.slice(uri.lastIndexOf("/") + 1).indexOf(".") === -1) {
    // /findings -> /findings.html; anything with an extension (/_next/..., .txt) is a file.
    request.uri = uri + ".html";
  }
  return request;
}
