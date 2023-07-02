<#
.SYNOPSIS
    OPSI PS Integration

.DESCRIPTION
    Automatisches installieren des Client Agents
    und Programme anhand vorhandener Clients
.NOTES
    Filename: Auto_Opsi.ps1
    Author: Matthias W.
    Modified date: 02.07.2023
    Version 1.1
#>

$Global:OPSIWebSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$Global:EndPoint = "192.168.2.102:4447"

#region OPSI Session

function New-OPSISession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$User,
        [Parameter(Mandatory = $true)]
        [string]$Passwort,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint        
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("x-opsi-session-lifetime", "900")
    $headers.Add("Content-Type", "application/json")

    
    $body = "{`"username`":`"$User`",`"password`":`"$Passwort`"}"
    
    try {
        $response = Invoke-WebRequest "https://$Endpoint/session/login" -Method 'POST' -Headers $headers -Body $body -WebSession $Global:OPSIWebSession
        return ConvertFrom-Json $response.Content
    }
    catch {
        Write-Host $_
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "Fehler beim Login" -ForegroundColor Red
            return $null
        }
        else {
            write-Host "Loginfehler: "$_.Exception.Response.StatusCode -ForegroundColor Red
            return $null
        }
    }

}
function Close-OPSISession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint     
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    try {
        $response = Invoke-WebRequest "https://$Endpoint/session/logout" -Method 'POST'-WebSession $Session -Body ""
        return  ConvertFrom-Json $response.Content
    }
    catch {
        Write-Host $_ -ForegroundColor Red
        return $false
    }
}

#endregion

#region RestAPI
function Invoke-RawRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory=$true)]
        [string]$Endpoint,     
        [Parameter(Mandatory=$true)]
        [string]$Content     
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("X-Requested-With", "XMLHttpRequest")
        $Body =  $Content
        $response = Invoke-WebRequest "https://$Endpoint/rpc" -Method 'POST' -Headers $headers -Body $Body  -WebSession $Session
        return ConvertFrom-Json $response.Content
    }
    catch {
        Write-Host "Invoke-RawRequest Error : " $Content "`n$_"
        return $null
    }
}
function Get-ClientIDs {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint     
    )
    $Content = ConvertTo-Json @{
        'id'      = '1'
        'jsonrpc' = '2.0'
        'method'  = 'getClientIds_list'
        'params'  = @{}
    }
    return Invoke-RawRequest -Session $Session -Endpoint $Endpoint -Content $Content
}
function Get-ProductIds {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint     
    )
    $Content = ConvertTo-Json @{
        'id'      = '1'
        'jsonrpc' = '2.0'
        'method'  = 'getProductIds_list'
        'params'  = @{}
    }
    return Invoke-RawRequest -Session $Session -Endpoint $Endpoint -Content $Content
}
function Get-InstalledProducts {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $true)]
        [string]$Client        
    )
    $Content = ConvertTo-Json @{
        'id'      = '1'
        'jsonrpc' = '2.0'
        'method'  = 'getInstalledLocalBootProductIds_list'
        'params'  = @($Client)
    }
    return Invoke-RawRequest -Session $Session -Endpoint $Endpoint -Content $Content
}
function Confirm-ProductStatus {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $true)]
        [string]$Client,
        [Parameter(Mandatory = $true)]
        [string]$Product,
        [Parameter(Mandatory = $true)]
        [ValidateSet("none", "setup", "update", "uninstall")]
        [string]$ProduktAktion         
    )
    $Content = ConvertTo-Json @{
        'id'      = '1'
        'jsonrpc' = '2.0'
        'method'  = 'setProductActionRequest'
        'params'  = @($Product, $Client, $ProduktAktion)
    }
    return Invoke-RawRequest -Session $Session -Endpoint $Endpoint -Content $Content
}
function Confirm-HostFireEvent {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $true)]
        [string]$Client
    ) 
    $Content = ConvertTo-Json @{
        'id'      = '1'
        'jsonrpc' = '2.0'
        'method'  = 'hostControl_fireEvent'
        'params'  = @("on_demand", $Client)
    }
    return Invoke-RawRequest -Session $Session -Endpoint $Endpoint -Content $Content
}
#endregion

#region Toolset
function Select-Objects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$jsonResult     
    )
    Clear-Host
    Write-Host "Bitte waehlen Sie die zu installierenden Programmen aus."
    Write-Host "Zum bestaetigen druecken Sie die ESC Tasten.`n" 

    $tmpItems = New-Object System.Collections.Generic.Dictionary"[String,bool]"

    $originalPosition = $Host.UI.RawUI.CursorPosition
    $curY = 0

    foreach ($prop in $jsonResult.'result') {
        $tmpItems.Add($prop, [bool]::Parse('false'))
        Write-Host $prop.PadRight(50) ("False").PadRight(10) ("[ ]").PadRight(10)
    }


    [Console]::SetCursorPosition(0, 0)
    [Console]::CursorVisible = [bool]::Parse('false')

    while ($true) {
        $key = $host.UI.RawUI.ReadKey('IncludeKeyDown, NoEcho')

        if ($key.VirtualKeyCode -eq '87' -or $key.VirtualKeyCode -eq '38') {
            [Console]::SetCursorPosition(0, $originalPosition.Y + $curY)
            $keyName = $tmpItems.Keys | Select-Object -Index $curY
            Write-Host $keyName.PadRight(50) ($tmpItems[$keyName].ToString()).PadRight(10) ("[ ]").PadRight(10) -ForegroundColor White -NoNewline
            if ($curY -eq 0) {
                $curY = $tmpItems.Count - 1
            }
            else {
                $curY -= 1
            }
            [Console]::SetCursorPosition(0, ($originalPosition.Y + $curY))
            $keyName = $tmpItems.Keys | Select-Object -Index $curY
            Write-Host $keyName.PadRight(50) ($tmpItems[$keyName].ToString()).PadRight(10) ("[*]").PadRight(10) -ForegroundColor Green -NoNewline
        }
        elseif ($key.VirtualKeyCode -eq '40' -or $key.VirtualKeyCode -eq '83') {
            [Console]::SetCursorPosition(0, $originalPosition.Y + $curY)
            $keyName = $tmpItems.Keys | Select-Object -Index $curY
            Write-Host $keyName.PadRight(50) ($tmpItems[$keyName].ToString()).PadRight(10) ("[ ]").PadRight(10) -ForegroundColor White -NoNewline
            if ($curY -eq $tmpItems.Count - 1) {
                $curY = 0
            }
            else {
                $curY += 1
            }
            [Console]::SetCursorPosition(0, ($originalPosition.Y + $curY))
            $keyName = $tmpItems.Keys | Select-Object -Index $curY
            Write-Host $keyName.PadRight(50) ($tmpItems[$keyName].ToString()).PadRight(10) ("[*]").PadRight(10) -ForegroundColor Green -NoNewline
        }
        elseif ($key.VirtualKeyCode -eq '13') {
            [Console]::SetCursorPosition(0, ($originalPosition.Y + $curY))
            $keyName = $tmpItems.Keys | Select-Object -Index $curY
            $tmpItems[$keyName] = -not([bool]::Parse($tmpItems[$keyName]))
            Write-Host $keyName.PadRight(50) ($tmpItems[$keyName].ToString()).PadRight(10) ("[*]").PadRight(10) -ForegroundColor Green -NoNewline
        }
        elseif ($key.VirtualKeyCode -eq '27') {
            Clear-Host
            break
        }
    }
    $bk = $tmpItems.GetEnumerator().Where({ $_.Value.ToString() -eq 'true' }) | ForEach-Object { $_.Key.ToString() }
    return $bk
}
function Enter-Client {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$jsonResult     
    )
    $clients = New-Object System.Collections.Generic.Dictionary"[Int,String]"
    foreach ($prop in $jsonResult.'result') {
        $clients.Add($clients.Count, $prop)
    }
    while ($true) {
        Clear-Host
        $clients | Format-Table | Out-Host
        Write-Host "Zum beenden geben Sie -1 ein."
        $output = Read-Host -Prompt  "Bitte geben Sie den Namen oder den Key ein"
        if ($output -eq "-1") { Exit 0 }
        if ($output -match "^\d+$") {
            #Key
            if ($clients.ContainsKey($output)) {
                return $clients.Item($output)
            }
        }
        else {
            #Name
            if ($clients.ContainsValue($output)) {
                return $output
            }
        }
    }
}
function Install-OPSI_ClientAgent{
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Passwort,
        [Parameter(Mandatory=$true)]
        [string]$ClientName
    )
    try{
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $Dest = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path + "\oca.exe"
        $sc = "https://" + $Global:EndPoint  + "/public/opsi-client-agent/opsi-client-agent-installer.exe"
        (New-Object System.Net.WebClient).DownloadFile($sc, $Dest)
        $params = " --service-address " + $Global:EndPoint + " --service-username " + $Username + " --service-password "  + $Passwort + " --client-id " + $ClientName + " --no-gui"
        Start-Process -FilePath $Dest -ArgumentList $params -Wait
    }catch{
        Write-Host $_
    }
}
#endregion

#region Main
function Main {
    $username = ""
    $pass = ""
    while ($true) {
        Clear-Host
        Write-Host "OPSI Powershell Connect 1.1`n" -ForegroundColor Green
        $username = Read-Host -Prompt "Bitte geben Sie Ihren Usernamen ein"
        $securePWd = Read-Host -Prompt "Bitte geben Sie Ihr Passwort ein" -AsSecureString
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
        $response = New-OPSISession -User $username -Passwort $pass -Endpoint $Global:EndPoint
        if (-not($null -eq $response)) {
            Clear-Host
            Write-Host "Erfolgreich verbunden!`nDruecke eine Taste..." -ForegroundColor Green
            Read-Host
            break 
        }
        else {
            Clear-Host
            Write-Host "Verbindung konnte nicht aufgebaut werden!`nDruecke eine Taste..." -ForegroundColor Yellow
            $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ErrorAction SilentlyContinue
            if($null -eq $key){
                #Ersteinrichtung skippen
                Write-Host ""
                Write-Host "Die Ersteinrichtung vom Internetexplorer ist nicht abgeschlossen." -ForegroundColor Yellow
                Write-Host "Setze Registry Key um Einrichtung zu skippen" -ForegroundColor Yellow
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
                Write-Host  "Eintrag wurde gesetzt. Drücke Enter." -ForegroundColor Green
                Read-Host
            }
            Read-Host
        }
    }

    while ($true) {
        Clear-Host
        Write-Host "OPSI Powershell Connect 1.1`n" -ForegroundColor Green
        Write-Host "1. Hosts anzeigen."
        Write-Host "2. Produkte anzeigen."
        Write-Host "3. Produkt installieren."
        Write-Host "4. Produkte anhand Hosts installieren."
        Write-Host "5. Install OPSI-Client-Agent"
        Write-Host "6. Close Session & Exit.`n"
        $Eingabe = Read-Host -Prompt "Eingabe"
        switch ($Eingabe) {
            "1" {  
                $response = Get-ClientIDs -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                if (-not($null -eq $response)) { 
                    Clear-Host
                    Write-Host "Host IDs empfangen.`n" -ForegroundColor Green 
                    $response.'result' | Format-Table -AutoSize
                    Read-Host -Prompt "`nDruecke eine beliebige Taste"
                } else{Write-Host ERROR; Read-Host}         
            }
            "2" { 
                $response = Get-ProductIds -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                if (-not($null -eq $response)) { 
                    Clear-Host
                    Write-Host "Produkte empfangen.`n" -ForegroundColor Green 
                    $response.'result' | Format-Table -AutoSize
                    Read-Host -Prompt "`nDruecke eine beliebige Taste"
                }
            }
            "3" {  
                $response = Get-ClientIDs -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                if (-not($null -eq $response)) { 
                    Clear-Host
                    Write-Host "Host IDs empfangen.`n" -ForegroundColor Green 
                    $response.'result' | Format-Table -AutoSize
                }else{break} 
                while($true){
                    $fqdn = Read-Host "`nBitte geben Sie einen Host (FQDN) an"
                    if($response.'result' -contains $fqdn){
                        break
                    }
                } 
                Write-Host "Rufe verfuegbare Produktinformationen ab..."
                $response = Get-ProductIds -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                if (-not($null -eq $response)) { 
                    $ToInstall = Select-Objects -jsonResult $response
                } else{Write-Host ERROR; Read-Host;break}
                #Produkte die installiert werden sollen sind vorhanden
                #Vergleichen mit Produkten die bereits installiert sind
                $response = Get-InstalledProducts -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $fqdn
                if ($null -eq $response) {Write-Host ERROR ;Read-Host;break} 
                foreach($prod in $ToInstall){
                    #Ist es installiert?
                    if($response.'result' -contains $prod){
                        Write-Host $prod "ist installiert." -ForegroundColor Green
                    }else{
                        Write-Host $prod "wird installiert." -ForegroundColor Magenta
                        Confirm-ProductStatus -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $fqdn -Product $prod -ProduktAktion setup > $null
                    }
                }
                #OnDemand auslösen
                Confirm-HostFireEvent -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $fqdn > $null
            }
            "4" {  
                $response = Get-ClientIDs -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                if (-not($null -eq $response)) { 
                    Clear-Host
                    Write-Host "Host IDs empfangen.`n" -ForegroundColor Green 
                    $response.'result' | Format-Table -AutoSize
                }else{break} 
                while($true){
                    $Spiegel = Read-Host "`nBitte geben Sie einen Host (FQDN) zum Spiegeln an"
                    if($response.'result' -contains $Spiegel){
                        break
                    }
                } 
                while($true){
                    $Dest = Read-Host "`nBitte geben Sie den Zielhost (FQDN) an"
                    if($response.'result' -contains $Dest){
                        break
                    }
                } 
                $mirror = Get-InstalledProducts -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $Spiegel
                if ($null -eq $response) {Write-Host ERROR ;Read-Host;break} 
                $mirrorDest = Get-InstalledProducts -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $Dest
                if ($null -eq $response) {Write-Host ERROR ;Read-Host;break} 
                foreach($prod in $mirror.'result'){
                    #Ist es installiert?
                    if($mirrorDest.'result' -contains $prod){
                        Write-Host $prod "ist installiert." -ForegroundColor Green
                    }else{
                        Write-Host $prod "wird installiert." -ForegroundColor Magenta
                        Confirm-ProductStatus -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $Dest -Product $prod -ProduktAktion setup > $null
                    }
                }
                #OnDemand auslösen
                Confirm-HostFireEvent -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint -Client $Dest > $null
                Read-Host
            }
            "5"{
                if((Read-Host -Prompt "Auf diesem PC wird der OPSI Client Agent installiert? (j/n)") -ccontains "j"){
                    $response = Get-ClientIDs -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint
                    if ($null -eq $response) { 
                        Write-Host "Fehler beim empfagen bereits eingetragener Hosts" -ForegroundColor Red
                    }
                    while($true){
                        $fqdn = Read-Host "`nBitte geben Sie einen Host (FQDN) an"
                        if(-not($response.'result' -contains $fqdn)){
                            Write-Host "Der FQDN " $fqdn " ist noch verfuegbar." -ForegroundColor Green
                            break
                        }
                    }
                    Install-OPSI_ClientAgent -Username $username -Passwort $pass -ClientName $fqdn
                    Write-host "Ende Installation"
                    Read-Host
                }
            }
            "6" {  
                Clear-Host
                $response = Close-OPSISession -Session $Global:OPSIWebSession -Endpoint $Global:EndPoint 
                if (-not($null -eq $response)) { 
                    Write-Host "Erfolgreich abgemeldet!" -ForegroundColor Green 
                    Read-Host
                    Exit 0
                }
                else { Exit -1 }
            }
            Default {}
        }
    }
}
Main
exit 0
#endregion

