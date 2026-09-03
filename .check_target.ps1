try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/' -TimeoutSec 5 -UseBasicParsing
    Write-Output ('8099 OK: ' + $r.StatusCode)
    Write-Output ('Title: ' + $r.ParsedHtml.title)
} catch {
    Write-Output ('8099 FAIL: ' + $_.Exception.Message)
}
