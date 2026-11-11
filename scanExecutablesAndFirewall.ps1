# scanExecutablesAndFirewall.ps1
# Lista los procesos con conexiones activas y permite bloquear su salida a red
# (solo el ejecutable o todos los .exe de su carpeta) con reglas de Firewall.

function Salir {
    Write-Host ""
    Read-Host "Presione Enter para salir" | Out-Null
    exit
}

# ------------------------------------------------------------------
# 1) Permisos de administrador (necesarios para crear reglas de Firewall)
# ------------------------------------------------------------------
$identidad = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$esAdmin   = $identidad.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $esAdmin) {
    Write-Host "Se necesitan permisos de administrador. Reabriendo el script elevado..."
    # -ExecutionPolicy Bypass solo afecta a esta ejecucion, asi arranca
    # aunque la politica actual no permita scripts.
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# ------------------------------------------------------------------
# Crea una regla de bloqueo de salida para un ejecutable
# ------------------------------------------------------------------
function Nueva-ReglaBloqueo {
    param([string]$Ruta)

    $nombre   = [IO.Path]::GetFileNameWithoutExtension($Ruta)
    $ruleName = "BLOCK_$nombre"

    $existentes = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
    if ($existentes.Count -gt 0) {
        $mismoPrograma = $existentes | Get-NetFirewallApplicationFilter | Where-Object Program -eq $Ruta
        if ($mismoPrograma) {
            Write-Host "  Ya existia:  $ruleName"
            return
        }
        # Mismo nombre de exe pero en otra carpeta: se diferencia el nombre
        $ruleName = "BLOCK_$nombre ($(Split-Path $Ruta -Parent))"
    }

    try {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Description $Ruta `
            -Direction Outbound `
            -Program $Ruta `
            -Action Block `
            -Profile Any `
            -ErrorAction Stop | Out-Null
        Write-Host "  Creada:      $ruleName"
    }
    catch {
        Write-Host "  Error:       $Ruta -> $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------
# 2) Procesos con conexiones activas
# ------------------------------------------------------------------
Clear-Host

Write-Host "Procesos con conexiones activas"
Write-Host "==============================="
Write-Host ""

$procesos = @(
    Get-NetTCPConnection |
    Where-Object State -eq Established |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object {
        try {
            $proc = Get-Process -Id $_ -ErrorAction Stop
            $ruta = (Get-CimInstance Win32_Process -Filter "ProcessId=$_").ExecutablePath

            [PSCustomObject]@{
                Nombre = $proc.ProcessName
                PID    = $_
                Ruta   = $ruta
            }
        }
        catch {
        }
    } |
    Sort-Object Nombre
)

if ($procesos.Count -eq 0) {
    Write-Host "No hay procesos con conexiones establecidas."
    Salir
}

$contador = 1
foreach ($p in $procesos) {
    Write-Host "[$contador] $($p.Nombre)"
    $contador++
}

Write-Host ""
$opcion = Read-Host "Seleccione numero"

$n = 0
if (-not [int]::TryParse($opcion, [ref]$n) -or $n -lt 1 -or $n -gt $procesos.Count) {
    Write-Host "Seleccion invalida"
    Salir
}

$p = $procesos[$n - 1]

Write-Host ""
Write-Host "Proceso:"
Write-Host "Nombre: $($p.Nombre)"
Write-Host "PID:    $($p.PID)"
Write-Host "Ruta:   $($p.Ruta)"
Write-Host ""

Get-NetTCPConnection |
Where-Object OwningProcess -eq $p.PID |
Format-Table RemoteAddress, RemotePort, State

if ([string]::IsNullOrWhiteSpace($p.Ruta)) {
    Write-Host "No se pudo obtener la ruta del ejecutable (proceso del sistema o sin acceso)."
    Write-Host "No se puede crear una regla para este proceso."
    Salir
}

# ------------------------------------------------------------------
# 3) Que bloquear
# ------------------------------------------------------------------
$carpeta = Split-Path $p.Ruta -Parent

Write-Host "Que desea bloquear?"
Write-Host "[1] Solo este ejecutable"
Write-Host "[2] Todos los .exe de la carpeta: $carpeta"
Write-Host "[3] Todos los .exe de la carpeta y sus subcarpetas"
Write-Host "[0] Nada (salir)"
Write-Host ""
$modo = Read-Host "Opcion"

switch ($modo) {
    '1' {
        Write-Host ""
        Nueva-ReglaBloqueo -Ruta $p.Ruta
    }

    { $_ -in '2', '3' } {
        # Bloquear carpetas enteras de Windows deja el sistema sin red
        if ($carpeta.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host ""
            Write-Host "La carpeta pertenece a Windows ($env:windir)."
            Write-Host "Por seguridad no se bloquea la carpeta completa; use la opcion 1."
            Salir
        }

        $recursivo = ($modo -eq '3')
        $exes = @(Get-ChildItem -Path $carpeta -Filter *.exe -File -Recurse:$recursivo -ErrorAction SilentlyContinue)

        if ($exes.Count -eq 0) {
            Write-Host "No se encontraron .exe en $carpeta"
            Salir
        }

        Write-Host ""
        Write-Host "Se van a bloquear $($exes.Count) ejecutables:"
        foreach ($exe in $exes) {
            Write-Host "  $($exe.FullName)"
        }
        Write-Host ""

        $respuesta = Read-Host "Confirmar? (S/N)"
        if ($respuesta -notmatch '^[sS]$') {
            Write-Host "Cancelado."
            Salir
        }

        Write-Host ""
        foreach ($exe in $exes) {
            Nueva-ReglaBloqueo -Ruta $exe.FullName
        }
    }

    default {
        Write-Host "Sin cambios."
        Salir
    }
}

Write-Host ""
Write-Host "Listo."
Salir
