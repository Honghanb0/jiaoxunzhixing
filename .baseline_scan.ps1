# 基线扫描脚本：登录 -> 确保域名存在 -> 触发扫描 -> 等待 -> 获取结果
$ErrorActionPreference = 'Stop'
$baseUrl = 'http://127.0.0.1:8080'

# 1. 登录获取 token
$loginBody = @{username='admin'; password='Admin@123'} | ConvertTo-Json
$loginResp = Invoke-WebRequest -Uri "$baseUrl/api/auth/login" -Method POST -Body $loginBody -ContentType 'application/json' -TimeoutSec 10 -UseBasicParsing
$loginData = $loginResp.Content | ConvertFrom-Json
$token = $loginData.token
if (-not $token) { Write-Output 'LOGIN FAILED'; exit 1 }
Write-Output 'Login OK'

$headers = @{Authorization = "Bearer $token"}

# 2. 获取域名列表，找到或创建 8099 靶场域名
$domainsResp = Invoke-WebRequest -Uri "$baseUrl/api/domains" -Headers $headers -TimeoutSec 10 -UseBasicParsing
$domains = $domainsResp.Content | ConvertFrom-Json
$targetDomain = $domains | Where-Object { $_.name -like '*8099*' } | Select-Object -First 1

if (-not $targetDomain) {
    Write-Output 'Domain 8099 not found, creating...'
    $createBody = @{
        name='http://127.0.0.1:8099'
        description='漏洞扫描测试靶场'
        max_depth=3
        max_pages=50
        status='active'
    } | ConvertTo-Json
    $createResp = Invoke-WebRequest -Uri "$baseUrl/api/domains" -Method POST -Body $createBody -ContentType 'application/json' -Headers $headers -TimeoutSec 10 -UseBasicParsing
    $targetDomain = $createResp.Content | ConvertFrom-Json
    Write-Output ("Created domain: " + $targetDomain.name + " (id=" + $targetDomain.id + ")")
} else {
    Write-Output ("Target domain: " + $targetDomain.name + " (id=" + $targetDomain.id + ")")
}

# 3. 触发扫描
$scanBody = @{domain_id=$targetDomain.id} | ConvertTo-Json
$scanResp = Invoke-WebRequest -Uri "$baseUrl/api/scan/start" -Method POST -Body $scanBody -ContentType 'application/json' -Headers $headers -TimeoutSec 10 -UseBasicParsing
$scanData = $scanResp.Content | ConvertFrom-Json
$scanJobId = $scanData.job_id
Write-Output ("Scan job started: " + $scanJobId)

# 4. 等待扫描完成
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 2
    try {
        $progressResp = Invoke-WebRequest -Uri ("$baseUrl/api/scan/" + $scanJobId + "/progress") -Headers $headers -TimeoutSec 10 -UseBasicParsing
        $progress = $progressResp.Content | ConvertFrom-Json
        Write-Output ("  [$i] status=" + $progress.status + " page=" + $progress.current_page + "/" + $progress.total_pages + " vulns=" + $progress.vuln_found)
        if ($progress.status -eq 'completed' -or $progress.status -eq 'failed' -or $progress.status -eq 'timeout') { break }
    } catch {
        Write-Output ("  [$i] progress query error: " + $_.Exception.Message)
    }
}

# 5. 获取扫描结果
$resultResp = Invoke-WebRequest -Uri ("$baseUrl/api/scan/" + $scanJobId + "/results") -Headers $headers -TimeoutSec 15 -UseBasicParsing
$results = $resultResp.Content | ConvertFrom-Json

# 6. 保存完整结果到 JSON 文件
$results | ConvertTo-Json -Depth 10 | Out-File -FilePath '.\baseline_before.json' -Encoding UTF8

Write-Output ""
Write-Output "=== BASELINE SCAN RESULTS ==="
Write-Output ("ScanJobID: " + $scanJobId)
Write-Output ("Total vulns: " + $results.summary.total_vulnerabilities)
Write-Output ("High: " + $results.summary.high_severity + " Medium: " + $results.summary.medium_severity + " Low: " + $results.summary.low_severity)
Write-Output ("Pages: " + $results.summary.total_pages)
Write-Output ("Sensitive infos: " + $results.sensitive_infos.Count)
Write-Output ""
Write-Output "=== Vulnerability Details ==="
foreach ($v in $results.vulnerabilities) {
    Write-Output ("[" + $v.severity + "] " + $v.type + " | " + $v.name + " | url=" + $v.url)
}
Write-Output ""
Write-Output "=== Results saved to baseline_before.json ==="
