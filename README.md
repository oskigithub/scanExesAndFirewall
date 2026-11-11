# scanExesAndFirewall

Script de PowerShell para Windows que lista los procesos con conexiones de red activas y permite bloquear su salida a Internet con reglas del Firewall de Windows.

## Qué hace

1. Muestra los procesos con conexiones TCP establecidas.
2. Elegís uno y te muestra su ruta y a dónde está conectado.
3. Podés bloquear:
   - solo ese ejecutable,
   - todos los `.exe` de su carpeta,
   - o todos los `.exe` de la carpeta y sus subcarpetas.

Las reglas se crean como `BLOCK_<nombre>` (salida, todos los perfiles).

## Uso
Antes de correr → Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine.
Clic derecho en `scanExesAndFirewall.ps1` → **Ejecutar con PowerShell**. El script pide permisos de administrador solo.

## Quitar una regla

```powershell
Remove-NetFirewallRule -DisplayName "BLOCK_nombre"
```
