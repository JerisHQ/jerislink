<#
.SYNOPSIS
  Checks an installed JerisLink MSIX serves its Explorer "Send to JerisLink" command.

.DESCRIPTION
  Creates the command's class ({8C96D31C-0D45-435B-B555-9465096C2E8A}, the
  Clsid in AppxManifest.xml.in) from outside the package, the way Explorer
  does. Windows serves it from the package's COM surrogate (dllhost.exe
  loading JerisLinkSendTo.dll), so this proves the manifest registration, the
  DLL exports and the class factory work in the installed package. Then checks
  the title, the icon (Jerislink.exe in the install folder), the canonical name
  and the flags. It does not click the menu or send a file: Invoke starts the
  viewer, which needs a Mac to send to.

.PARAMETER InstallLocation
  The package's install folder (Get-AppxPackage).InstallLocation.
#>
param(
    [Parameter(Mandatory)][string]$InstallLocation
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace JerisLinkCheck {
    [ComImport, Guid("a08ce4d0-fa25-44ab-b57c-c7b1c323e0b9"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IExplorerCommand {
        [return: MarshalAs(UnmanagedType.LPWStr)] string GetTitle(IntPtr items);
        [return: MarshalAs(UnmanagedType.LPWStr)] string GetIcon(IntPtr items);
        [PreserveSig] int GetToolTip(IntPtr items, out IntPtr tip);
        Guid GetCanonicalName();
        uint GetState(IntPtr items, [MarshalAs(UnmanagedType.Bool)] bool okToBeSlow);
        void Invoke(IntPtr items, IntPtr bindCtx);
        uint GetFlags();
        [PreserveSig] int EnumSubCommands(out IntPtr commands);
    }

    // The class is served out of process, so the object PowerShell gets is a
    // plain __ComObject. A C# cast does the QueryInterface; a PowerShell cast
    // does not, so the calls are made here.
    public static class Probe {
        public static string[] Read(object o) {
            var c = (IExplorerCommand)o;
            return new[] { c.GetTitle(IntPtr.Zero), c.GetIcon(IntPtr.Zero),
                           c.GetCanonicalName().ToString(), c.GetFlags().ToString() };
        }
    }
}
'@

$clsid = [Guid]'8C96D31C-0D45-435B-B555-9465096C2E8A'
$type = [Type]::GetTypeFromCLSID($clsid, $true)
$cmd = [Activator]::CreateInstance($type)
$title, $icon, $nameText, $flagsText = [JerisLinkCheck.Probe]::Read($cmd)
$name = [Guid]$nameText
$flags = [uint32]$flagsText
Write-Host "title: $title"
Write-Host "icon: $icon"
Write-Host "canonical name: $name, flags: $flags"

$wantIcon = (Join-Path $InstallLocation 'Jerislink.exe') + ',-101'
if ($title -ne 'Send to JerisLink') { throw "title is '$title'" }
if ($icon -ne $wantIcon) { throw "icon is '$icon', expected '$wantIcon'" }
if ($name -ne $clsid) { throw "canonical name is $name" }
if ($flags -ne 0) { throw "flags are $flags, expected ECF_DEFAULT (0)" }

# Out of process: a dllhost.exe from the package has the DLL loaded.
$dll = Join-Path $InstallLocation 'JerisLinkSendTo.dll'
$host_ = Get-Process dllhost -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Modules.FileName -contains $dll } catch { $false }
} | Select-Object -First 1
if (-not $host_) { throw "no dllhost.exe has $dll loaded" }
Write-Host "served by dllhost.exe pid $($host_.Id)"

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($cmd)
Write-Host 'OK: Send to JerisLink command is served by the installed package'
