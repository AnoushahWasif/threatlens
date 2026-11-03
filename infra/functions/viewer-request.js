// CloudFront Function (cloudfront-js-2.0), viewer request. Maps clean URLs to the files a
// Next.js static export writes. Kept to ES5 so it runs on the Functions runtime as is.
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // Next 16 prefetches /a/b/__next.a.b.__PAGE__.txt, but the export writes it as
  // /a/b/__next.a/b/__PAGE__.txt (decision 18).
  var prefetch = uri.match(/^(.*\/)__next\.([^\/]+)\.__PAGE__\.txt$/);
  if (prefetch) {
    request.uri = prefetch[1] + "__next." + prefetch[2].split(".").join("/") + "/__PAGE__.txt";
    return request;
  }

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
