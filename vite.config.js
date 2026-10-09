function rewriteToAndroidDownloadPage(request, _response, next) {
  const pathname = new URL(request.url ?? '/', 'http://localhost').pathname

  if (pathname === '/' || pathname === '/index.html' || pathname === '/download') {
    request.url = '/download.html'
  }

  next()
}

export default {
  plugins: [
    {
      name: 'android-download-homepage',
      configureServer(server) {
        server.middlewares.use(rewriteToAndroidDownloadPage)
      },
      configurePreviewServer(server) {
        server.middlewares.use(rewriteToAndroidDownloadPage)
      },
    },
  ],
}
