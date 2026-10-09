const apkUrl = '/downloads/private-notes-android.apk'
const downloadButton = document.querySelector('#download-button')
const downloadStatus = document.querySelector('#download-status')

async function enableDownloadWhenPublished() {
  try {
    const response = await fetch(apkUrl, { method: 'HEAD', cache: 'no-store' })
    const contentType = response.headers.get('content-type')?.split(';')[0].trim()
    if (!response.ok || contentType !== 'application/vnd.android.package-archive') {
      downloadStatus.textContent =
        'The signed Android installer is not available at this address yet. Please check back later.'
      return
    }

    downloadButton.href = apkUrl
    downloadButton.removeAttribute('aria-disabled')
    downloadButton.removeAttribute('tabindex')
    downloadButton.classList.remove('is-disabled')
    downloadButton.textContent = 'Download Android app'
    downloadStatus.textContent =
      'Signed APK download. Android may ask you to confirm installation from your browser.'
  } catch (error) {
    console.error('Could not check Android installer availability.', error)
    downloadStatus.textContent =
      'Could not check the installer right now. Check your connection and try again.'
  }
}

void enableDownloadWhenPublished()
