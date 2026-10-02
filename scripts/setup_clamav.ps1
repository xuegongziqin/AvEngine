<#
.SYNOPSIS
    ClamAV 完整安装配置脚本（修复版）
#>

param(
    [string]$MsiFile = "$PSScriptRoot\..\bina\clamav.msi",
    [string]$ConfigYaml = "$PSScriptRoot\..\config.yaml",
    [string]$ClamavDir = "$env:ProgramFiles\ClamAV",
    [string]$ServiceName = "clamd",
    [int]$Port = 3310
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "ClamAV 配置"

function Write-Step { Write-Host "[$(Get-Date -Format HH:mm:ss)] $args" -ForegroundColor Cyan }
function Write-Done { Write-Host "    -> 完成" -ForegroundColor Green }
function Write-Err { Write-Host "    -> 错误: $args" -ForegroundColor Red }
function Write-Warn { Write-Host "    -> 警告: $args" -ForegroundColor Yellow }

# 管理员检查
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Err "请以管理员身份运行。"
    exit 1
}

$clamdExe = "$ClamavDir\clamd.exe"
$clamdConf = "$ClamavDir\clamd.conf"
$freshclamConf = "$ClamavDir\freshclam.conf"
$freshclamExe = "$ClamavDir\freshclam.exe"
$dbDir = "$ClamavDir\db"

# 安装 MSI
if (-NOT (Test-Path $clamdExe)) {
    Write-Step "安装 ClamAV..."
    if (-NOT (Test-Path $MsiFile)) { Write-Err "未找到 $MsiFile"; exit 1 }
    Start-Process msiexec.exe -ArgumentList "/i `"$MsiFile`" /quiet /norestart" -Wait
    if (!(Test-Path $clamdExe)) { Write-Err "安装失败"; exit 1 }
    Write-Done
} else {
    Write-Step "ClamAV 已安装，跳过安装。"
}

# 创建必备目录
if (-NOT (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }

# clamd.conf
Write-Step "配置 clamd.conf..."
if (Test-Path $clamdConf) { Copy-Item $clamdConf "$clamdConf.bak" -Force }
@"
TCPSocket $Port
TCPAddr 0.0.0.0
MaxThreads 50
LogFile $ClamavDir\clamd.log
LogTime yes
DatabaseDirectory $dbDir
"@ | Set-Content -Path $clamdConf -Encoding ASCII
Write-Done

# freshclam.conf
Write-Step "配置 freshclam.conf..."
if (Test-Path $freshclamConf) { Copy-Item $freshclamConf "$freshclamConf.bak" -Force }
@"
DatabaseMirror database.clamav.net
DatabaseDirectory $dbDir
UpdateLogFile $ClamavDir\freshclam.log
LogTime yes
"@ | Set-Content -Path $freshclamConf -Encoding ASCII
Write-Done

# 运行 freshclam（重试直到成功或用户中断）
Write-Step "更新病毒库 (freshclam)..."
if (Test-Path $freshclamExe) {
    $retry = 3
    while ($retry -gt 0) {
        Write-Host "    尝试下载病毒库 (剩余尝试次数: $retry) ..."
        $proc = Start-Process $freshclamExe -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Done
            break
        } else {
            Write-Warn "freshclam 返回错误代码 $($proc.ExitCode)，可能是网络或配置问题。"
            $retry--
            if ($retry -gt 0) {
                Write-Host "    等待 5 秒后重试..."
                Start-Sleep -Seconds 5
            }
        }
    }
    if ($retry -eq 0) {
        Write-Warn "无法自动更新病毒库，clamd 可能无法启动。"
    }
} else {
    Write-Warn "未找到 freshclam.exe，请手动下载病毒库到 $dbDir"
}

# 注册并启动服务
Write-Step "配置 clamd 服务..."
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
$binPath = "`"$clamdExe`" --config-file=`"$clamdConf`""
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName "ClamAV Daemon" -StartupType Automatic | Out-Null
Write-Done

Write-Step "启动 clamd 服务..."
try {
    Start-Service $ServiceName -ErrorAction Stop
    Write-Done
} catch {
    Write-Warn "服务启动失败，尝试前台诊断..."
    # 前台运行
    Write-Host "    前台运行 clamd 以查看错误..."
    $debugProc = Start-Process $clamdExe -ArgumentList "--config-file=`"$clamdConf`" --debug" -NoNewWindow -PassThru
    Start-Sleep -Seconds 4
    if ($debugProc.HasExited) {
        Write-Err "clamd 立即退出，请检查日志或手动运行: cd '$ClamavDir'; .\clamd.exe --config-file=clamd.conf --debug"
    } else {
        Write-Host "    clamd 正在前台运行，按任意键停止并尝试后台服务..." -ForegroundColor Green
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Stop-Process $debugProc -Force
        try {
            Start-Service $ServiceName -ErrorAction Stop
            Write-Done
        } catch {
            Write-Err "服务最终启动失败，请手动排查。"
        }
    }
}

# 更新 config.yaml（不存在则复制 config.example.yaml，随后统一写入端口）
Write-Step "更新项目 config.yaml..."
if (-NOT (Test-Path $ConfigYaml)) {
    $exampleYaml = "$PSScriptRoot\..\config.example.yaml"
    if (Test-Path $exampleYaml) {
        Copy-Item $exampleYaml $ConfigYaml -Force
    } else {
        Set-Content -Path $ConfigYaml -Value "clamav:`n  host: `"127.0.0.1`"`n  port: $Port`n  timeout: 30`n" -Encoding UTF8
    }
}

$yaml = Get-Content $ConfigYaml -Raw
if ($yaml -match '(?m)^clamav:') {
    $yaml = $yaml -replace '(?ms)^clamav:.*?(?=\n\S|\z)', "clamav:`n  host: `"127.0.0.1`"`n  port: $Port`n  timeout: 30"
} else {
    $yaml += "`n`nclamav:`n  host: `"127.0.0.1`"`n  port: $Port`n  timeout: 30`n"
}
Set-Content -Path $ConfigYaml -Value $yaml -Encoding UTF8
Write-Done

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  ClamAV 配置完成" -ForegroundColor Green
Write-Host "  地址: 127.0.0.1:$Port" -ForegroundColor Green
Write-Host "  服务状态: $(Get-Service $ServiceName | Select-Object -ExpandProperty Status)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
if ((Get-Service $ServiceName).Status -ne 'Running') {
    Write-Host "如果服务未运行，请检查病毒库是否下载成功: ls '$dbDir'" -ForegroundColor Yellow
}
Read-Host "按 Enter 退出"