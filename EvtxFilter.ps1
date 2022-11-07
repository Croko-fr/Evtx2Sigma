<#
.SYNOPSIS

Search script for easy Evtx lookup and SIGMA rule generation.

.DESCRIPTION
With this script you will be able to get informations from evtx files.
You can query a Log for a single or more EventId(s).
You can list all EventIds from a specific Log.
You can search for an EventId and a specific value for another field.
You can generate a SIGMA rule from your search.

.PARAMETER ListLog
Switch to list all logs available on the system.
Result : gives RecordCount per LogName

.PARAMETER LogSearch
Gives the scope of the search. Must be a valid Logname.
Defaults to the Security log.

.INPUTS
None. You cannot pipe objects to Add-Extension.

.OUTPUTS
Screen output or file output as json or sigma rule.

.EXAMPLE
List all Logs with corresponding number of events.
PS> EvtxFilter -ListLog

.EXAMPLE
Get the EventId list from Events in the current  `Application` log.
PS> EvtxFilter -LogSearch Application -ListEventId

.EXAMPLE
Search `Security` log and shows all the events corresponding to selected EventId.
PS> EvtxFilter -LogSearch 'Security' -EventId 4627

.EXAMPLE
Search `Security` log and shows all the events corresponding to selected **EventId** that match a specific **Field** and a specific **FieldValue**.
PS> EvtxFilter -LogSearch 'Security' -EventId 4627 -Field 'LogonType' -FieldValue 2

.EXAMPLE
Search `Security` log and shows all the events that match a specific **Field** and DON'T match a specific **FieldValue**.
PS> EvtxFilter -LogSearch Security -Field "ProcessId" -NotFieldValue "5924"

.EXAMPLE
Search `Security` log and shows **only one** event corresponding to selected **EventId**.
PS> EvtxFilter -LogSearch 'Security' -EventId 4624 -OnlyOne

.EXAMPLE
Search `Security` log for an event corresponding to selected **EventId** and shows **only one** event as **a SIGMA rule**.
PS> EvtxFilter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma

.EXAMPLE
Search `Security` log for an event corresponding to selected **EventId** and outputs **only one** event as **a SIGMA rule** writen in the **OutDir** `./results/`.
PS> EvtxFilter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma -OutDir ./results/

.EXAMPLE
Search `Security` log for all events corresponding to selected **EventId** and outputs **all events** as **SIGMA rules** writen in the **OutDir** `./results/`.
PS> EvtxFilter -LogSearch 'Security' -EventId 4624 -ConvertToSigma -OutDir ./results/

.EXAMPLE
Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the last **30 minutes TimeFrame**.
PS> EvtxFilter -LogSearch 'Microsoft-Windows-Sysmon/Operational' -TimeFrame 30m 

Possible values exemples : 15s / 30m / 12h / 7d / 3M

.EXAMPLE
Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the specified **Period** between **-Begin** datetime and **-End** datetime.
PS> EvtxFilter -LogSearch "Microsoft-Windows-Sysmon/Operational" -Period -Begin  "2021-12-20T10:00:00.000" -End  "2021-12-20T11:00:00.000"

.EXAMPLE
Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the last **1 hour** and outputs on screen as a timeline.
PS> EvtxFilter -LogSearch "Microsoft-Windows-Sysmon/Operational" -TimeFrame 1h -ConvertToTimeLine

.LINK
Online version: https://www.github.com/croko-fr/Evtx2Sigma

#>


# TimeLine Object class to get a clear output that will allow Out-GridView format
class TimeLine {

    [string]$TimeStamp
    [string]$ComputerName
    [string]$Action
    [string]$Description

    TimeLine([string]$TimeStamp,[string]$ComputerName,[string]$Action,[string]$Description) {
        $this.TimeStamp = $TimeStamp
        $this.ComputerName = $ComputerName
        $this.Action = $Action
        $this.Description = $Description
    }

}

# Show "Null" string when desired if $null
function ShowIfNull {
    param (
        $DataToCheck
    )
    if ( $null -eq $DataToCheck ) {
        return "Null"
    } else {
        return $DataToCheck
    }

}

# Show "All" string when value is "*"
function ShowIfAll {
    param (
        $DataToCheck
    )
    if ( "*" -eq $DataToCheck ) {
        return "All"
    } else {
        return $DataToCheck
    }
    
}

function FirewallProfile {
    param (
        [string]$StringToProcess
    )
    switch ( $StringToProcess ) {
        2          { Return "Prive" }
        4          { Return "Public" }
        2147483649 { Return "Aucun"  }
    }
}

function FirewallProtocol {
    param (
        [string]$StringToProcess
    )

    Switch ( $StringToProcess ) {
        "0"    { Return "HOPOPT" }
        "1"    { Return "ICMPv4" }
        "2"    { Return "IGMP" }
        "6"    { Return "TCP" }
        "17"   { Return "UDP" }
        "41"   { Return "IPv6" }
        "43"   { Return "IPv6-Route" }
        "44"   { Return "IPv6-Frag" }
        "47"   { Return "GRE" }
        "58"   { Return "ICMPv6" }
        "59"   { Return "IPv6-NoNxt" }
        "60"   { Return "IPv6-Opts" }
        "112"  { Return "VRRP" }
        "113"  { Return "PGM" }
        "115"  { Return "L2TP" }
        "256"  { Return "ALL" }
        default { Return "NotFound" }
    }
}

function Sanitize {
    param (
        [string]$StringToProcess
    )
    $StringSanitized = $StringToProcess.Replace("é","e")
    $StringSanitized = $StringSanitized.Replace("è","e")
    $StringSanitized = $StringSanitized.Replace("ê","e")
    $StringSanitized = $StringSanitized.Replace("É","e")
    $StringSanitized = $StringSanitized.Replace("à","e")
    $StringSanitized = $StringSanitized.Replace("ù","u")
    $StringSanitized = $StringSanitized.Replace("\","_")
    $StringSanitized = $StringSanitized.Replace("/","_")
    $StringSanitized = $StringSanitized.Replace(":","_")
    $StringSanitized = $StringSanitized.Replace('"',"_")
    $StringSanitized = $StringSanitized.Replace("'","_")
    $StringSanitized = $StringSanitized.Replace("=","_")
    $StringSanitized = $StringSanitized.Replace("<","_")
    $StringSanitized = $StringSanitized.Replace(">","_")
    return $StringSanitized
}

function AuditSubCategory {
    param (
        $InputGuid
    )

# List Generated with : `auditpol.exe /list /SubCategory:* /v /r` and columns renamed
$SubCategoryCSV = "SubCategory,Guid
Système,{69979848-797A-11D9-BED3-505054503030}
Modification de l’état de la sécurité,{0CCE9210-69AE-11D9-BED3-505054503030}
Extension système de sécurité,{0CCE9211-69AE-11D9-BED3-505054503030}
Intégrité du système,{0CCE9212-69AE-11D9-BED3-505054503030}
Pilote IPSEC,{0CCE9213-69AE-11D9-BED3-505054503030}
Autres événements système,{0CCE9214-69AE-11D9-BED3-505054503030}
Ouverture/Fermeture de session,{69979849-797A-11D9-BED3-505054503030}
Ouvrir la session,{0CCE9215-69AE-11D9-BED3-505054503030}
Fermer la session,{0CCE9216-69AE-11D9-BED3-505054503030}
Verrouillage du compte,{0CCE9217-69AE-11D9-BED3-505054503030}
Mode principal IPsec,{0CCE9218-69AE-11D9-BED3-505054503030}
Mode rapide IPsec,{0CCE9219-69AE-11D9-BED3-505054503030}
Mode étendu IPsec,{0CCE921A-69AE-11D9-BED3-505054503030}
Ouverture de session spéciale,{0CCE921B-69AE-11D9-BED3-505054503030}
Autres événements d’ouverture/fermeture de session,{0CCE921C-69AE-11D9-BED3-505054503030}
Serveur NPS,{0CCE9243-69AE-11D9-BED3-505054503030}
Revendications utilisateur/de périphérique,{0CCE9247-69AE-11D9-BED3-505054503030}
Appartenance à un groupe,{0CCE9249-69AE-11D9-BED3-505054503030}
Accès aux objets,{6997984A-797A-11D9-BED3-505054503030}
Système de fichiers,{0CCE921D-69AE-11D9-BED3-505054503030}
Registre,{0CCE921E-69AE-11D9-BED3-505054503030}
Objet de noyau,{0CCE921F-69AE-11D9-BED3-505054503030}
SAM,{0CCE9220-69AE-11D9-BED3-505054503030}
Services de certification,{0CCE9221-69AE-11D9-BED3-505054503030}
Généré par application,{0CCE9222-69AE-11D9-BED3-505054503030}
Manipulation de handle,{0CCE9223-69AE-11D9-BED3-505054503030}
Partage de fichiers,{0CCE9224-69AE-11D9-BED3-505054503030}
Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030}
Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030}
Autres événements d’accès à l’objet,{0CCE9227-69AE-11D9-BED3-505054503030}
Partage de fichiers détaillé,{0CCE9244-69AE-11D9-BED3-505054503030}
Stockage amovible,{0CCE9245-69AE-11D9-BED3-505054503030}
Stratégie centralisée intermédiaire,{0CCE9246-69AE-11D9-BED3-505054503030}
Utilisation de privilège,{6997984B-797A-11D9-BED3-505054503030}
Utilisation de privilèges sensibles,{0CCE9228-69AE-11D9-BED3-505054503030}
Utilisation de privilèges non sensibles,{0CCE9229-69AE-11D9-BED3-505054503030}
Autres événements d’utilisation de privilèges,{0CCE922A-69AE-11D9-BED3-505054503030}
Suivi détaillé,{6997984C-797A-11D9-BED3-505054503030}
Création du processus,{0CCE922B-69AE-11D9-BED3-505054503030}
Fin du processus,{0CCE922C-69AE-11D9-BED3-505054503030}
Activité DPAPI,{0CCE922D-69AE-11D9-BED3-505054503030}
Événements RPC,{0CCE922E-69AE-11D9-BED3-505054503030}
Événements Plug-and-Play,{0CCE9248-69AE-11D9-BED3-505054503030}
Événements de jeton ajustés à droite,{0CCE924A-69AE-11D9-BED3-505054503030}
Changement de stratégie,{6997984D-797A-11D9-BED3-505054503030}
Modification de la stratégie d’audit,{0CCE922F-69AE-11D9-BED3-505054503030}
Modification de la stratégie d’authentification,{0CCE9230-69AE-11D9-BED3-505054503030}
Modification de la stratégie d’autorisation,{0CCE9231-69AE-11D9-BED3-505054503030}
Modification de la stratégie de niveau règle MPSSVC,{0CCE9232-69AE-11D9-BED3-505054503030}
Modification de la stratégie de plateforme de filtrage,{0CCE9233-69AE-11D9-BED3-505054503030}
Autres événements de modification de stratégie,{0CCE9234-69AE-11D9-BED3-505054503030}
Gestion des comptes,{6997984E-797A-11D9-BED3-505054503030}
Gestion des comptes d’utilisateur,{0CCE9235-69AE-11D9-BED3-505054503030}
Gestion des comptes d’ordinateur,{0CCE9236-69AE-11D9-BED3-505054503030}
Gestion des groupes de sécurité,{0CCE9237-69AE-11D9-BED3-505054503030}
Gestion des groupes de distribution,{0CCE9238-69AE-11D9-BED3-505054503030}
Gestion des groupes d’applications,{0CCE9239-69AE-11D9-BED3-505054503030}
Autres événements de gestion des comptes,{0CCE923A-69AE-11D9-BED3-505054503030}
Accès DS,{6997984F-797A-11D9-BED3-505054503030}
Accès au service d’annuaire,{0CCE923B-69AE-11D9-BED3-505054503030}
Modification du service d’annuaire,{0CCE923C-69AE-11D9-BED3-505054503030}
Réplication du service d’annuaire,{0CCE923D-69AE-11D9-BED3-505054503030}
Réplication du service d’annuaire détaillé,{0CCE923E-69AE-11D9-BED3-505054503030}
Connexion de compte,{69979850-797A-11D9-BED3-505054503030}
Validation des informations d’identification,{0CCE923F-69AE-11D9-BED3-505054503030}
Opérations de ticket du service Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030}
Autres événements d’ouverture de session,{0CCE9241-69AE-11D9-BED3-505054503030}
Service d’authentification Kerberos,{0CCE9242-69AE-11D9-BED3-505054503030}"

    ForEach ( $AuditSubCategory in ($SubCategoryCSV | ConvertFrom-Csv) ) {
        if ( $AuditSubCategory.Guid -match $InputGuid ) {
                $ResultStr = $AuditSubCategory.SubCategory
        }
    }
    Return $ResultStr

}

function AuditPolicyChanges {
    Param (
        $Value
    )
    switch ( $Value.Replace(" ","") ) {
        "%%8448" { Return "Non Configuré" }
        "%%8449" { Return "Succes" }
        "%%8450" { Return "Echec" }
        "%%8451" { Return "Succes et Echec" }
    }
}

function AdminWarning {

    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Warning "Insufficient permissions only limited results will be shown."
    }

}


function AdminRequired {

    Write-Host "[+] Checking for Required elevated permissions..."
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Warning "Insufficient permissions. Open the PowerShell console as an administrator and run this script again."
        EndScript
    }

}


function EndScript {
    Exit
}

function EvtxFilter {

    Param (
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="ListLog" )]
        [Switch] $ListLog,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogSearch" )]
        [String] $LogSearch,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogPath" )]
        [String] $LogPath,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Parameter( ParameterSetName="RawSearch" )]
        [String] $RawSearch,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Parameter( ParameterSetName="ListEventId" )]
        [Switch] $ListEventId,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $EventId,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $Field,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $FieldValue,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $NotFieldValue,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Parameter( ParameterSetName="RawSearch" )]
        [Switch] $OnlyOne,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Switch] $ConvertToSigma,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $OutDir,
        [ValidatePattern("[0-9]{1,2}[smhdM]")]
        [String] $TimeFrame,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Switch] $Period,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [ValidatePattern("[0-9-:TZ]{1,}")]
        [String] $Begin,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Parameter( ParameterSetName="Period" )]
        [ValidatePattern("[0-9-:TZ]{1,}")]
        [String] $End,
        [String] $CatalogFile = "EventId_List_Full_sort_uniq.txt",
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Switch] $ConvertToTimeLine = $false
    )


    Write-Host "     _____       _         _____ _ _ _            "
    Write-Host "    | ____|_   _| |___  __|  ___(_) | |_ ___ _ __ "
    Write-Host "    |  _| \ \ / / __\ \/ /| |_  | | | __/ _ \ '__|"
    Write-Host "    | |___ \ V /| |_ >  < |  _| | | | ||  __/ |   "
    Write-Host "    |_____| \_/  \__/_/\_\|_|   |_|_|\__\___|_|   "
    Write-Host "                                                      "
    Write-Host "                                           by Croko-fr"
    Write-Host "                                                      "


    ForEach ( $Parameter in $PSBoundParameters.GetEnumerator() ) {

        Switch ( $Parameter.Key ) {

            "ListLog" {
                        AdminWarning
                        Write-Host "[+] Listing computer eventLogs"
                        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Select-Object RecordCount,LogName | Where-Object { $_.RecordCount -ne 0 -and $null -ne $_.RecordCount } | Sort-Object RecordCount -Descending
                        break
                    }

            "LogPath" {
                        Try {
                            $null = Test-Path -Path $LogPath -ErrorAction Stop
                            $FullLogPath = Resolve-Path $LogPath -ErrorAction Stop
                            Write-Host "[+] Searching EventLog : $FullLogPath"
                            $XmlQuery = "<QueryList> <Query Id='0' Path='file://$FullLogPath'> <Select Path='file://$FullLogPath'> "
                            $Request = "Get-WinEvent -Path '$FullLogPath'"
                        } Catch {
                            Write-Host "[x] No EventLog found with path : $LogPath"
                            Return
                        }
                        break
                    }

            "LogSearch" {
                        AdminRequired
                        $LogName = (Get-WinEvent -ListLog * | Where-Object { $_.Logname -eq "$LogSearch" }).LogName
                        if ( $LogName -eq $LogSearch ) {
                            Write-Host "[+] Searching EventLog : $LogSearch"
                            $XmlQuery = "<QueryList> <Query Id='0' Path='$LogSearch'> <Select Path='$LogSearch'> "
                            $Request = "Get-WinEvent -LogName '$LogSearch'"
                        } Else {
                            Write-Host "[x] No EventLog found with name : $LogSearch"
                            return
                        }
                        break
                    }

            "RawSearch" {
                        AdminRequired
                        Write-Debug "[+] Searching with Raw keyword : '$RawSearch'"
                        $match = Invoke-Expression $Request | Where-Object -Property Message -Match '$RawSearch' | Sort-Object TimeCreated -Descending
                        if ( $match.count -ne 0 ) {
                            Write-Host "[+] Match found :"
                            $match
                        } else {
                            Write-Host "[x] Keyword not found."
                            Break
                        }
                        break
                    }

            "ListEventId" {
                        AdminWarning
                        Write-Debug "[+] Searching EventID list."
                        $ListOfEventId = Invoke-Expression $Request | Select-Object Id | Sort-Object Id -Unique

                        if ( $ListOfEventId.count -ne 0 ) {

                            $ListOfEventId.Id
                            If ( $PSBoundParameters.ContainsKey('OutDir') ) {
                                Write-Host "[+] Storing SIGMA rules in directory : $OutDir"
                                ForEach ( $SearchId in $ListOfEventId.Id ) {
                                    If ( $PSBoundParameters.ContainsKey('LogSearch') ) {
                                        EvtxFilter -LogSearch $LogSearch -EventId $SearchId -OnlyOne -ConvertToSigma -OutDir $OutDir
                                    }
                                    If ( $PSBoundParameters.ContainsKey('LogPath') ) {
                                        EvtxFilter -LogPath $LogPath -EventId $SearchId -OnlyOne -ConvertToSigma -OutDir $OutDir
                                    }
                                }            
                            }

                        } else {

                            Write-Host "[x] EventLog seems to be empty."
                            Break

                        }
                        break
                    }

            "EventId" {
                        Write-Debug "[+] Searching EventId  : $EventId"
                        if ( $Ids = $EventId.split(",") ) {
                            $EventIdQuery = "*[System[EventID=" + $Ids[0]
                            for ($i=1; $i -lt $Ids.Count; $i++) {
                                $EventIdQuery += " or EventID=" + $Ids[$i]
                            }
                            $EventIdQuery += "]]"
                        } else {
                            $EventIdQuery = "*[System[EventID=$EventId]]"
                        }
                        break
                    }
            "FieldValue" {
                        Write-Debug "[+] Searching Field    : $Field=$FieldValue"
                        $FieldQuery = "*[EventData[Data[@Name='$Field']='$FieldValue'] or System[($Field='$FieldValue')]]"
                        break
                    }
            "NotFieldValue" {
                        Write-Debug "[+] Searching Field    : $Field!=$NotFieldValue"
                        $FieldQuery = "*[EventData[Data[@Name='$Field']!='$NotFieldValue'] or System[($Field!='$NotFieldValue')]]"
                        break
                    }
            "TimeFrame" {
                        Write-Debug "[+] Limiting search on TimeFrame : $TimeFrame"
                        if ( $TimeFrame.Contains("s") ) { $Number = $TimeFrame.Split("s"); $seconde = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddSeconds(-$seconde).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        if ( $TimeFrame.Contains("m") ) { $Number = $TimeFrame.Split("m"); $minute = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddMinutes(-$minute).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        if ( $TimeFrame.Contains("h") ) { $Number = $TimeFrame.Split("h"); $hour = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1-$hour).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        if ( $TimeFrame.Contains("d") ) { $Number = $TimeFrame.Split("d"); $jour = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddDays(-$jour).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        if ( $TimeFrame.Contains("M") ) { $Number = $TimeFrame.Split("M"); $month = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddMonths(-$month).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        Write-Debug "[+] Search begin : $Begin"
                        $End = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Write-Debug "[+] Search end   : $End"
                        $TimeFrameQuery = "*[System[TimeCreated[@SystemTime&gt;='$Begin' and @SystemTime&lt;='$End']]]"
                        break
                    }
            "Period" {
                        Write-Debug "[+] Limiting search on Period :"
                        Try { Get-Date -Date "$Begin" | Out-Null } Catch { Write-Host -ForegroundColor Red "[x] Period : BEGIN date is not valid."; break }
                        Try { Get-Date -Date "$End" | Out-Null } Catch { Write-Host -ForegroundColor Red "[x] Period : END date is not valid."; break }
                        $Begin = (Get-Date -date "$Begin" ).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Write-Debug "[+] Search begin : $Begin"
                        $End = (Get-Date -date "$End" ).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Write-Debug "[+] Search end   : $End"
                        $TimeFrameQuery = "*[System[TimeCreated[@SystemTime&gt;='$Begin' and @SystemTime&lt;='$End']]]"
                        break
                    }
        }

    }


    If ( -not $PSBoundParameters.ContainsKey('ListEventId') -and -not $PSBoundParameters.ContainsKey('ListLog') ) {

        if ( $EventIdQuery -and $FieldQuery -and $TimeFrameQuery ) {
            $XmlQuery += $EventIdQuery + " and " + $FieldQuery + " and " + $TimeFrameQuery
        } else {
            if ( $EventIdQuery ) {
                $XmlQuery += $EventIdQuery
                if ( $FieldQuery ) {
                    $XmlQuery += " and " + $FieldQuery
                }
                if ( $TimeFrameQuery ) {
                    $XmlQuery += " and " + $TimeFrameQuery
                }
            } else {
                if ( $FieldQuery -and $TimeFrameQuery ) {
                    $XmlQuery += $FieldQuery + " and " + $TimeFrameQuery
                } else {
                    if ( $FieldQuery ) { $XmlQuery += $FieldQuery }
                    if ( $TimeFrameQuery ) { $XmlQuery += $TimeFrameQuery }
                    if ( -not $FieldQuery -and -not $TimeFrameQuery ) { $XmlQuery += "*" }
                }
            }
        }

        $XmlQuery += " </Select> </Query> </QueryList>"

        Write-Debug "[+] XPath query : $XmlQuery"

        if ( $PSBoundParameters.ContainsKey('OnlyOne') ) {
            $Request = 'Get-WinEvent -FilterXml "' + $XmlQuery + '" -MaxEvent 1 -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending'
        } else {
            $Request = 'Get-WinEvent -FilterXml "' + $XmlQuery + '" -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending'
        }
        
        Write-Debug "[+] Launching XPath REQUEST : $Request"

        $Events = Invoke-Expression $Request

        if ( $Events.Count -eq 0 ) {

            Write-Host "[x] No matching event found."

        } else {

            Write-Debug "[+] Matching events found"
            Write-Host "[+]"$Events.Count"matching event found."

            ForEach ( $Event in $Events ) {

                $eventXML = [xml]$Event.ToXml()
                $System = @{}
                $UserData = @{}
                $EventData = @{}
                $LogType = ""

                $System.add( "Provider_Name" , $eventXML.Event.System.Provider.Name )
                $System.add( "Guid" , $eventXML.Event.System.Provider.Guid )
                if ( $eventXML.Event.System.Provider.EventSourceName ) {
                    $System.add( "EventSourceName" , $eventXML.Event.System.Provider.EventSourceName )
                }

                for ($i=1; $i -lt $eventXML.Event.System.ChildNodes.Count; $i++) {

                    switch ( $eventXML.Event.System.ChildNodes[$i].Name ) {
                        "Execution"   {
                                        $System.add( "ThreadID" , $eventXML.Event.System.Execution.ThreadID )
                                        $System.add( "ProcessID" , $eventXML.Event.System.Execution.ProcessID )
                                        break
                                        }
                        "TimeCreated" {
                                        $System.add( "SystemTime" , $eventXML.Event.System.TimeCreated.SystemTime )
                                        break
                                        }
                        "Correlation" {
                                        if ( $eventXML.Event.System.Correlation.ActivityId ) {
                                            $System.add( "ActivityID" , $eventXML.Event.System.Correlation.ActivityID )
                                        }
                                        break
                                        }
                        "Security"    {
                                        if ( $eventXML.Event.System.Security.UserID ) {
                                            $System.add( "UserID" , $eventXML.Event.System.Security.UserID )
                                        }
                                        break
                                        }
                        "EventID"    {
                                        if ( $null -eq $eventXML.Event.System.EventID.'#text' ) {
                                            $System.add( "EventID" , $eventXML.Event.System.EventID )
                                        } else { 
                                            $System.add( "EventID" , $eventXML.Event.System.EventID.'#text' )
                                            if ( $eventXML.Event.System.EventID.Qualifiers ) {
                                                $System.add( "Qualifiers" , $eventXML.Event.System.EventID.Qualifiers )
                                            }
                                        }
                                        break
                                        }
                        default       {
                                        If ( ( $null -ne $eventXML.Event.System.ChildNodes[$i].'#text' ) -Or ( $eventXML.Event.System.ChildNodes[$i].'#text' -ne "NULL" ) ) {
                                            $System.add( $eventXML.Event.System.ChildNodes[$i].Name , $eventXML.Event.System.ChildNodes[$i].'#text' )
                                        }
                                        break
                                        }
                    }
                }

                for ($i=0; $i -lt $eventXML.Event.UserData.FirstChild.ChildNodes.Count; $i++) {
                    $LogType = "UserData"
#                    if ( $null -ne $eventXML.Event.UserData.ChildNodes[$i].'#text' ) {
                        if ( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name -eq "Data" ) {
                            $UserData.add( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name+$i , $eventXML.Event.UserData.FirstChild.ChildNodes[$i].'#text' )
                        } else {
                            $UserData.add( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name , $eventXML.Event.UserData.FirstChild.ChildNodes[$i].'#text' )
                        }
#                    }
                }
                for ($i=0; $i -lt $eventXML.Event.EventData.ChildNodes.Count; $i++) {
                    $LogType = "EventData"
#                    if ( $null -ne $eventXML.Event.EventData.ChildNodes[$i].'#text' ) {
                        if ( $eventXML.Event.EventData.ChildNodes[$i].Name -eq "Data" ) {
                            $EventData.add( $eventXML.Event.EventData.ChildNodes[$i].Name+$i , $eventXML.Event.EventData.ChildNodes[$i].'#text' )
                        } else {
                            $EventData.add( $eventXML.Event.EventData.ChildNodes[$i].Name , $eventXML.Event.EventData.ChildNodes[$i].'#text' )
                        }
#                    }
                }

                if ( $PSBoundParameters.ContainsKey('ConvertToSigma') -eq $true ) {

                    $Result = [String]"title: " + $System.Provider_Name + " EventID " + $System.EventID + "`r`n"
                    $Result += "id: " + (New-Guid).Guid + "`r`n"
                    # Find description for known EventID
                    $CatalogFilePath = (Get-Location).Path+"\"+$CatalogFile
                    if ( Test-Path $CatalogFilePath ) {
                        $Match = (( Get-Content $CatalogFilePath ) -match ($System.Provider_Name+";"+$System.EventID+";") ) -split ";"
                        if ( $Match ) {
                            $Description = Sanitize($Match[2])
                        } else {
                            $Description = $System.Provider_Name
                        }
                    } else {
                        $Description = $System.Provider_Name
                    }
                    $Result += "description: " + $Description + "`r`n"
                    $Result += "references:" + "`r`n"
                    $Result += "    - https://www.awesome-security-blog.com/vulns/cve-2021-xxxxx" + "`r`n"
                    $Result += "tags:" + "`r`n"
                    $Result += "    - cve-2021-xxxxx" + "`r`n"
                    $Result += "    - mitre.attack.txxxx.xxx" + "`r`n"
                    $Result += "status: stable / testing / experimental" + "`r`n"
                    $Result += "author: Croko" + "`r`n"
                    $Result += "date: " + (Get-Date).GetDateTimeFormats()[0] + "`r`n"
                    $Result += "modified: " + (Get-Date).GetDateTimeFormats()[0] + "`r`n"
                    $Result += "logsource:" + "`r`n"
                    $Result += "    product: windows" + "`r`n"
                    If ( $System.Channel ) {
                        $Result += "    service: " + $System.Channel.ToLower() + "`r`n"
                    } else {
                        $Result += "    service: " + $System.Provider_Name + "`r`n"
                    }
                    $Result += "detection:" + "`r`n"
                    $Result += "    selection:" + "`r`n"
                    foreach ( $Data in $System.Keys ) {
                            $Result += "        " + $Data + ": " + $System.$Data + "`r`n"
                    }

                    if ( ( $LogType -eq "EventData" ) -or ( $LogType -eq "UserData" ) ) {

                        $Result += "    filter:" + "`r`n"

                        foreach ( $Data in $(Get-Variable "$LogType" -ValueOnly).Keys ) {
    
                            if ( $null -eq ($(Get-Variable "$LogType" -ValueOnly).$Data ) ) {
                                $Result += "        " + $Data + ": null`r`n"
                            } else {

                                if ( (($(Get-Variable "$LogType" -ValueOnly).$Data).Split("`r`n")).Count -eq 1 ) {
    
                                    if ( ($(Get-Variable "$LogType" -ValueOnly).$Data).Contains(",") ) {
    
                                        $Result += "        $Data|contains:`r`n"
    
                                        $MultiLine = ($(Get-Variable "$LogType" -ValueOnly).$Data).Split(",")
                                        foreach ( $line in $MultiLine ) {
                                            if ( $line -ne "" ) {
                                                $Result += "            - " + $line.trim() + "`r`n"
                                            }
                                        }
    
                                    } else {
                                        
                                        if ( $Data -eq "Provider_Name" ) {
                                            $Result += "        LogName: " + $(Get-Variable "$LogType" -ValueOnly).$Data + "`r`n"
                                        } else {
                                            $Result += "        " + $Data + ": " + $(Get-Variable "$LogType" -ValueOnly).$Data + "`r`n"
                                        }
    
                                    }
    
                                } else {
    
                                    $Result += "        $Data|contains:`r`n"
    
                                    $MultiLine = ($(Get-Variable "$LogType" -ValueOnly).$Data).Split("`r`n")
                                    foreach ( $line in $MultiLine ) {
                                        if ( $line -ne "" ) {
                                            $Result += "            - " + $line.trim() + "`r`n"
                                        }
                                    }
    
                                }
                            }
                        }

                    }

                    $Result += "    timeframe: 15s / 30m / 12h / 7d / 3M" + "`r`n"
                    if ( ( $LogType -eq "EventData" ) -or ( $LogType -eq "UserData" ) ) {
                        $Result += "    condition: selection and filter" + "`r`n"
                    } else {
                        $Result += "    condition: selection" + "`r`n"
                    }
                    $Result += "fields:" + "`r`n"
                    foreach ( $SysData in $System.Keys ) {
                        $Result += "    - " + $SysData + "`r`n"
                    }
                    if ( ( $LogType -eq "EventData" ) -or ( $LogType -eq "UserData" ) ) {
                        foreach ( $Data in $(Get-Variable "$LogType" -ValueOnly).Keys ) {
                            $Result += "    - " + $Data + "`r`n"
                        }
                    }
                    $Result += "falsepositives:" + "`r`n"
                    $Result += "    - Explain what could be falsepositives / None" + "`r`n"
                    $Result += "level: informational / low / medium / high / critical" + "`r`n"

                }

                if ( $PSBoundParameters.ContainsKey('OutDir') ) {
        
                    if ( !(Test-Path $OutDir) ) {

                        Write-Host "[+] Creating output directory : $OutDir"
                        New-Item -Path $OutDir -type directory -Force | Out-Null

                    }

                    If ( $PSBoundParameters.ContainsKey('OnlyOne') ) { 

                        $FileName = $OutDir+"\Windows_EventLog_"+$System.Provider_Name+"_"+$System.EventId+"_"+($Description.Replace(".","")).Replace(" ","_")

                    } Else {

                        $FileName = $OutDir+"\Windows_EventLog_"+$System.Provider_Name+"_"+$System.EventId+"_"+($Description.Replace(".","")).Replace(" ","_")+"_"+$System.EventRecordID

                    }

                    If ( $PSBoundParameters.ContainsKey('ConvertToSigma') ) {

                        Write-Host "[+] Writing SIGMA rule : $Filename.yml"
                        Set-Content -Path $Filename".yml" -Value ( $Result )

                    } Else {
                    
                        Write-Host "[+] Writing Json file : $Filename.json"
                        Set-Content -Path $Filename".json" -Value ( $System | ConvertTo-Json )
                        Add-Content -Path $Filename".json" -Value ( $EventData | ConvertTo-Json )

                    }

                } else {
        
                    if ( $PSBoundParameters.ContainsKey('ConvertToSigma') ) {

                        $Result

                    } else {

                        if ( $PSBoundParameters.ContainsKey('ConvertToTimeLine') -eq $true ) {

                                Write-Debug "[+] ConvertToTimeline : $LogPath"

                            # Microsoft-Windows-AppID/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-AppID/Operational" ) -or ( $LogPath -match "Microsoft-Windows-AppID" ) ){

                                # File signing verification
                                if ( $System.EventID -eq 4004 ){

                                    if ( $null -eq $UserData.PublisherName ) { $UserData.PublisherName = "NotSigned" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File signing verification",$UserData.PublisherName+" --> "+$UserData.FilePath)

                                }

                            }

                            # Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant
                            if ( ( $LogSearch -eq "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" ) -or ( $LogPath -match "Microsoft-Windows-Application-Experience" ) ){

                                # Compatibility assistant file execution
                                if ( $System.EventID -eq 17 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File execution compatibility",$UserData.ResolverName+" --> "+$UserData.ExePath)

                                }

                            }

                            # Microsoft-Windows-AppLocker/EXE and DLL
                            if ( ( $LogSearch -match "Microsoft-Windows-AppLocker" ) -or ( $LogPath -match "Microsoft-Windows-AppLocker" ) ){

                                # Microsoft-Windows-AppLocker/EXE and DLL : execution allowed
                                if ( $System.EventID -eq 8002 ){

                                    if ( $UserData.FqbnLength -eq 1 ) { $SignStatus = "NotSigned" } else { $SignStatus = "Signed" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppLocker execution allowed : "+$UserData.PolicyName,"("+$UserData.TargetUser+") $SignStatus - "+$UserData.FullFilePath+" --> "+$UserData.FileHash)

                                }

                                # Microsoft-Windows-AppLocker/MSI and Script : execution allowed
                                if ( $System.EventID -eq 8005 ){

                                    if ( $UserData.FqbnLength -eq 1 ) { $SignStatus = "NotSigned" } else { $SignStatus = "Signed" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppLocker execution allowed : "+$UserData.PolicyName,"("+$UserData.TargetUser+") $SignStatus - "+$UserData.FilePath+" --> "+$UserData.FileHash)

                                }

                                # Microsoft-Windows-AppLocker/MSI and Script : execution denied
                                if ( $System.EventID -eq 8007 ){

                                    if ( $UserData.FqbnLength -eq 1 ) { $SignStatus = "NotSigned" } else { $SignStatus = "Signed" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppLocker execution denied : "+$UserData.PolicyName,"("+$UserData.TargetUser+") $SignStatus - "+$UserData.FilePath+" --> "+$UserData.FileHash)

                                }

                                # Microsoft-Windows-AppLocker_Packaged app-Execution : execution allowed
                                if ( $System.EventID -eq 8020 ){

                                    if ( $UserData.FqbnLength -eq 1 ) { $SignStatus = "NotSigned" } else { $SignStatus = "Signed" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppLocker execution allowed : "+$UserData.PolicyName,"("+$UserData.TargetUser+") $SignStatus - "+$UserData.Package)

                                }

                                # Microsoft-Windows-AppLocker/Packaged app-Deployment : installation allowed
                                if ( $System.EventID -eq 8023 ){

                                    if ( $UserData.FqbnLength -eq 1 ) { $SignStatus = "NotSigned" } else { $SignStatus = "Signed" }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppLocker installation allowed : "+$UserData.PolicyName,"("+$UserData.TargetUser+") $SignStatus - "+$UserData.Package)

                                }

                            }

                            # Microsoft-Windows-AppXDeploymentServer/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-AppXDeploymentServer/Operational" ) -or ( $LogPath -match "Microsoft-Windows-AppXDeploymentServer" ) ){

                                if ( $System.EventID -eq 821 ){

                                    if ( $EventData.ErrorCode -eq "0x0" ) { $ErrorCodeStr = "Successfull" } else { $ErrorCodeStr = "Error "+$EventData.ErrorCode }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"AppXDeployment : "+$ErrorCodeStr,"("+$EventData.UserSid+") "+$EventData.MainPackageFullName)

                                }

                            }

                            # Microsoft-Windows-Audio/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Audio/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Audio" ) ){

                                if ( $System.EventID -eq 65 ){

                                    Switch ( $EventData.NewState ) {
                                        "1" { $StateStr = "Connected" }
                                        "4" { $StateStr = "DisConnected" }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Audio device state : "+$StateStr,"Flow : "+$EventData.Flow+" "+$EventData.DeviceName+" --> "+$EventData.DeviceId)

                                }

                            }

                            # Microsoft-Windows-Bits-Client/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Bits-Client/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Bits-Client" ) ){

                                # Bits task launched by process
                                if ( $System.EventID -eq 3 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Bits task launched by process","("+$EventData.jobOwner+") jobId: "+$EventData.jobId+" "+$EventData.ProcessPath+" - "+$EventData.bytesTotal+" bytes --> "+$EventData.url)

                                }

                                # Bits task completed
                                if ( $System.EventID -eq 4 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Bits task completed","("+$EventData.jobOwner+") jobId: "+$EventData.jobId+" bytesTransferred : "+$EventData.bytesTransferred+" bytes --> for User : "+$EventData.User)

                                }

                                # Bits task file informations
                                if ( $System.EventID -eq 59 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Bits task file informations","jobId: "+$EventData.Id+" TimeStamp: "+$EventData.fileTime+" - Size: "+$EventData.bytesTotal+" bytes --> "+$EventData.url)

                                }

                                # Bits task file destination
                                if ( $System.EventID -eq 16403 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Bits task file destination","("+$EventData.jobOwner+") jobId: "+$EventData.jobId+" "+$EventData.RemoteName+" --> "+$EventData.LocalName)

                                }

                            }

                            # Microsoft-Windows-CodeIntegrity/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-CodeIntegrity/Operational" ) -or ( $LogPath -match "Microsoft-Windows-CodeIntegrity" ) ){

                                if ( $System.EventID -eq 3033 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Code Integrity : File did not meet the signing level requirements","RequestedPolicy:"+$EventData.RequestedPolicy+" ValidatedPolicy:"+$EventData.ValidatedPolicy+" "+$EventData.ProcessNameBuffer+" --> "+$EventData.FileNameBuffer)

                                }

                                if ( $System.EventID -eq 3089 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Signature information for another event","PID:"+$System.ProcessID+" PublisherName:"+$EventData.PublisherName+" --> IssuerName:"+$EventData.IssuerName)

                                }

                            }

                            # Microsoft-Windows-Crypto-DPAPI/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Crypto-DPAPI/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Crypto-DPAPI" ) ){

                                if ( $System.EventID -eq 12289 ){

                                    # HINT : User / UserSid mapping and connexion
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"DPAPI found credential key","UserName:"+$EventData.UserName+" UserSid:"+$EventData.UserSid)

                                }

                            }

                            # Microsoft-Windows-Dhcp-Client/Admin
                            if ( ( $LogSearch -eq "Microsoft-Windows-Dhcp-Client/Admin" ) -or ( $LogPath -match "Microsoft-Windows-Dhcp-Client" ) ){

                                if ( $System.EventID -eq 50066 ){

                                    # HINT : NetworkCard MacAddress --> Connexion to SSID
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"DHCP gave an address for SSID to HWaddr","SSID:"+$EventData.NetworkHintString+" <--> HWAddress:"+$EventData.HWAddress)

                                }

                                if ( $System.EventID -eq 50067 ){

                                    # HINT : NetworkCard MacAddress --> Connexion to SSID
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"DHCP received SSID for HWaddr","SSID:"+$EventData.NetworkHintString+" <--> HWAddress:"+$EventData.HWAddress)

                                }

                            }

                            # Microsoft-Windows-Diagnostics-Networking/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Diagnostics-Networking/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Diagnostics-Networking" ) ){

                                if ( $System.EventID -eq 1000 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network diagnostic started by user","PID:"+$System.ProcessID+" HelperClassName:"+$EventData.HelperClassName+" "+$EventData.HelperClassAttributes)

                                }

                            }

                            # Microsoft-Windows-Diagnostics-Performance/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Diagnostics-Performance/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Diagnostics-Performance" ) ){

                                if ( $System.EventID -eq 100 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Windows has started","UserBootInstance:"+$EventData.UserBootInstance+" BootStartTime:"+$EventData.BootStartTime+" --> BootEndTime:"+$EventData.BootEndTime)

                                }

                                if ( $System.EventID -eq 103 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Startup service degraded performances","Service:"+$EventData.Name+" Path:"+$EventData.Path+" ("+(ShowIfNull $EventData.CompanyName)+") "+(ShowIfNull $EventData.FriendlyName))

                                }

                                if ( $System.EventID -eq 109 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device led to degraded performances","Device:"+$EventData.Name+" Path:"+(ShowIfNull $EventData.Path)+" ("+(ShowIfNull $EventData.CompanyName)+") "+(ShowIfNull $EventData.FriendlyName))

                                }

                                if ( $System.EventID -eq 200 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Windows was shutdown","ShutdownIsDegradation:"+$EventData.ShutdownIsDegradation+" ShutdownStartTime:"+$EventData.ShutdownStartTime+" --> ShutdownEndTime:"+$EventData.ShutdownEndTime)

                                }

                                if ( $System.EventID -eq 203 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Service delayed shutdown","Service:"+$EventData.Name+" Path:"+$EventData.Path+" ("+(ShowIfNull $EventData.CompanyName)+") "+(ShowIfNull $EventData.FriendlyName))

                                }

                            }

                            # Microsoft-Windows-EapMethods-RasChap/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-EapMethods-RasChap/Operational" ) -or ( $LogPath -match "Microsoft-Windows-EapMethods-RasChap" ) ){

                                if ( $System.EventID -eq 100 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Successful authentication for user in the domain","PID:"+$System.ProcessID+" Domain:"+$EventData.Domain)

                                }

                                if ( $System.EventID -eq 107 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Sending credentials to server for user name","PID:"+$System.ProcessID+" Domain:"+$EventData.Domain)

                                }

                            }

                            # Microsoft-Windows-GroupPolicy/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-GroupPolicy/Operational" ) -or ( $LogPath -match "Microsoft-Windows-GroupPolicy" ) ){

                                if ( $System.EventID -eq 8004 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Manual processing of group policy done for computer","PID:"+$System.ProcessID+" IsMachine:"+$EventData.IsMachine+" PrincipalSamName:"+$EventData.PrincipalSamName)

                                }

                                # HINT : 8004 + 8005 within 0.30 second seams to mean that user executed : gpupdate /force
                                if ( $System.EventID -eq 8005 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Manual processing of group policy done for user","PID:"+$System.ProcessID+"IsMachine:"+$EventData.IsMachine+" PrincipalSamName:"+$EventData.PrincipalSamName)

                                }

                            }

                            # Microsoft-Windows-Kernel-PnP/Configuration
                            if ( ( $LogSearch -eq "Microsoft-Windows-Kernel-PnP/Configuration" ) -or ( $LogPath -match "Microsoft-Windows-Kernel-PnP" ) ){

                                if ( $System.EventID -eq 400 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device has been configured","Parent:"+$EventData.ParentDeviceInstanceId+" --> "+$EventData.DeviceInstanceId+" ( "+$EventData.DriverProvider+" - "+$EventData.DriverName+" - "+$EventData.DriverDate+")")

                                }

                                if ( $System.EventID -eq 410 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device has been started","ServiceName:"+$EventData.ServiceName+" --> "+$EventData.DeviceInstanceId+" ( "+$EventData.DriverName+" )")

                                }

                                if ( $System.EventID -eq 420 ){

                                    switch ( $EventData.Status ) {
                                        "0x0" { $StatusStr = "Success" }
                                        "0x1" { $StatusStr = "Error" }
                                        Default { $StatusStr = "Error-"+$EventData.Status }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device has been deleted",$EventData.DeviceInstanceId+" ( Status:"+$StatusStr+" - Problem:"+$EventData.Problem+" )")

                                }

                            }

                            # Microsoft-Windows-Kernel-ShimEngine/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Kernel-ShimEngine/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Kernel-ShimEngine" ) ){

                                if ( $System.EventID -eq 3 ){

                                    Switch ( $EventData.ShimSource ) {
                                        "0" { $SourceStr = "Registry" }
                                        "1" { $SourceStr = "Compatibility database" }
                                    }
                                    # TODO : What are Shims ??
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$SourceStr+" shims applied to Driver","AppliedGuids:"+$EventData.AppliedGuids+" --> "+$EventData.DriverName)

                                }

                                if ( $System.EventID -eq 4 ){

                                    Switch ( $EventData.FlagSource ) {
                                        "0" { $SourceStr = "registry" }
                                        "1" { $SourceStr = "compatibility database" }
                                    }
                                    # TODO : What are indicators ??
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$SourceStr+" indicators applied to device","Flags:"+$EventData.Flags+" DeviceName:"+$EventData.DeviceName)

                                }

                            }

                            # Microsoft-Windows-NcdAutoSetup/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-NcdAutoSetup/Operational" ) -or ( $LogPath -match "Microsoft-Windows-NcdAutoSetup" ) ){

                                if ( $System.EventID -eq 4001 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device connected to network","Network:"+$EventData.String1+" Info:"+(ShowIfNull $EventData.String2))

                                }

                                if ( $System.EventID -eq 4002 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device connected to network","Network:"+$EventData.String1)

                                }

                                if ( $System.EventID -eq 5001 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network qualified for autosetup","Network:"+$EventData.String1)

                                }

                                if ( $System.EventID -eq 5002 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network disqualified for autosetup by category","Network:"+$EventData.String1)

                                }

                                if ( $System.EventID -eq 5005 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network disqualified for autosetup by bits","Network:"+$EventData.String1+" Bits:"+$EventData.Integer1)

                                }

                            }

                            # Microsoft-Windows-NetworkProfile/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-NetworkProfile/Operational" ) -or ( $LogPath -match "Microsoft-Windows-NetworkProfile" ) ){

                                if ( $System.EventID -eq 10000 ){

                                    switch ( $EventData.Category ) {
                                        0 { $NetworkCategoryMap = "Public" }
                                        1 { $NetworkCategoryMap = "Private" }
                                        2 { $NetworkCategoryMap = "Domain Authenticated" }
                                    }
                                    switch ( $EventData.Type ) {
                                        0 { $NetworkTypeStr = "Unmanaged" }
                                        1 { $NetworkTypeStr = "Managed" }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network connected","State:"+$EventData.State+" Category:"+$NetworkCategoryMap+" Type:"+$NetworkTypeStr+" Network:"+$EventData.Name+" --> "+$EventData.Description)

                                }

                                if ( $System.EventID -eq 10001 ){

                                    switch ( $EventData.Category ) {
                                        0 { $NetworkCategoryMap = "Public" }
                                        1 { $NetworkCategoryMap = "Private" }
                                        2 { $NetworkCategoryMap = "Domain Authenticated" }
                                    }
                                    switch ( $EventData.Type ) {
                                        0 { $NetworkTypeStr = "Unmanaged" }
                                        1 { $NetworkTypeStr = "Managed" }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network disconnected","State:"+$EventData.State+" Category:"+$NetworkCategoryMap+" Type:"+$NetworkTypeStr+" Network:"+$EventData.Name+" --> "+$EventData.Description)

                                }

                            }

                            # Microsoft-Windows-NTLM/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-NTLM/Operational" ) -or ( $LogPath -match "Microsoft-Windows-NTLM" ) ){

                                if ( $System.EventID -eq 4001 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Outgoing NTLM authentication blocked","("+$EventData.ClientDomainName+"\"+$EventData.ClientUserName+") CallerPID:"+$System.CallerPID+" ProcessName:"+$EventData.ProcessName+" --> ("+$EventData.ClientDomainName+"\"+$EventData.ClientUserName+") "+$EventData.TargetName)

                                }

                            }

                            # Microsoft-Windows-Partition/Diagnostic
                            if ( ( $LogSearch -eq "Microsoft-Windows-Partition/Diagnostic" ) -or ( $LogPath -match "Microsoft-Windows-Partition" ) ){

                                if ( $System.EventID -eq 1006 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Diagnostic internal use only","DiskNumber:"+$EventData.DiskNumber+" Model:"+$EventData.Model+" SN:"+$EventData.SerialNumber+" Revision:"+$EventData.Revision)

                                }

                            }

                            # Microsoft-Windows-PowerShell/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-PowerShell/Operational" ) -or ( $LogPath -match "Microsoft-Windows-PowerShell" ) ){

                                if ( $System.EventID -eq 4104 ){

                                    # TODO : Reconstruct powershell script
                                    # ScriptBlockText : contains the Powershell script part
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Scriptblock text creation","PID:"+$System.ProcessID+" Message: "+$EventData.MessageNumber+"/"+$EventData.MessageTotal+" Id:"+$EventData.ScriptBlockId+" --> "+$EventData.Path)

                                }

                            }

                            # Microsoft-Windows-Security-Mitigations/KernelMode
                            if ( ( $LogSearch -eq "Microsoft-Windows-Security-Mitigations/KernelMode" ) -or ( $LogPath -match "Microsoft-Windows-Security-Mitigations" ) ){

                                if ( $System.EventID -eq 1 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Prohibit dynamic code - Always","CallingProcessId:"+$EventData.CallingProcessId+" "+$EventData.ProcessPath+" --> "+$EventData.ProcessCommandLine)

                                }

                                if ( $System.EventID -eq 2 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Prohibit dynamic code - Warning","CallingProcessId:"+$EventData.CallingProcessId+" "+$EventData.ProcessPath+" --> "+$EventData.ProcessCommandLine)

                                }

                                if ( $System.EventID -eq 3 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Prohibit child process creation - Always","CallingProcessId:"+$EventData.CallingProcessId+" "+$EventData.ProcessCommandLine+" --> "+$EventData.ChildCommandLine)

                                }

                                if ( $System.EventID -eq 10 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Prohibit win32k system calls - Warning","CallingProcessId:"+$EventData.CallingProcessId+" "+$EventData.ProcessPath+" --> "+$EventData.ProcessCommandLine)

                                }

                            }

                            # Microsoft-Windows-Shell-Core/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Shell-Core/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Shell-Core" ) ){

                                if ( $System.EventID -eq 9705 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Explorer EnumeratingRunKeyStart","PID:"+$System.ProcessID+" UserID:"+$System.UserID+" --> "+$EventData.KeyName)

                                }

                            }

                            # Microsoft-Windows-SmbClient/Connectivity
                            if ( ( $LogSearch -eq "Microsoft-Windows-SmbClient/Connectivity" ) -or ( $LogPath -match "Microsoft-Windows-SmbClient" ) ){

                                if ( $System.EventID -eq 30800 ){

                                    # TODO: find what generate this event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Unable to resolve server name","ServerName:"+$EventData.ServerName+" Status:"+$EventData.Status+" Reason:"+$EventData.Reason)

                                }

                                if ( $System.EventID -eq 30803 ){

                                    # TODO: can detect those commands when not working :
                                    #    net use \\MyServerThatDontExist\c$
                                    #    dir \\MyServerThatDontExist\c$
                                    # 3221226038 : Network path not found
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network connexion aborted","ServerName:"+$EventData.ServerName+" Status:"+$EventData.Status+" Reason:"+$EventData.Reason+" InstanceName:"+$EventData.InstanceName+" ConnectionType:"+$EventData.ConnectionType)

                                }

                                if ( $System.EventID -eq 30810 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"TCP_IP interface was installed","IfIndex:"+$EventData.IfIndex+" Name:"+$EventData.Name)

                                }

                                # TODO :
                                # if time between installed and deleted > 7 seconds means : Network interface connexion was active
                                # deleted then installed = 6 seconds means : Network interface disconnected ( connexion stops )
                                # deleted then installed < 2 seconds means : Network interface connected ( connexion begins )

                                if ( $System.EventID -eq 30811 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"TCP_IP interface was deleted","IfIndex:"+$EventData.IfIndex+" Name:"+$EventData.Name)

                                }

                                if ( $System.EventID -eq 30812 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"TDI interface was installed","ServerName:"+$EventData.ServerName)

                                }

                                if ( $System.EventID -eq 30813 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"TDI interface was deleted","ServerName:"+$EventData.ServerName)

                                }

                            }

                            # Microsoft-Windows-SmbClient/Security
                            if ( ( $LogSearch -eq "Microsoft-Windows-SmbClient/Security" ) -or ( $LogPath -match "Microsoft-Windows-SmbClient" ) ){

                                if ( $System.EventID -eq 31001 ){

                                    # TODO: Find right Description
                                    if ( $null -eq $EventData.UserName ) {
                                        $UserNameStr = "None"
                                    } else {
                                        $UserNameStr = $EventData.UserName
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Connexion unsuccessfull","("+$UserNameStr+") "+"ServerName:"+$EventData.ServerName+" "+$EventData.PrincipalName+" Status:"+$EventData.Status+" Reason:"+$EventData.Reason)

                                }

                            }

                            # Microsoft-Windows-SMBServer/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-SMBServer/Operational" ) -or ( $LogPath -match "Microsoft-Windows-SMBServer" ) ){

                                if ( $System.EventID -eq 1010 ){

                                    # TODO: Find real description
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Netbios Smb","("+$UserData.DomainName+"\"+$UserData.Name+") TransportName:"+$UserData.TransportName+" TransportFlags:"+$UserData.TransportFlags)

                                }

                            }

                            # Microsoft-Windows-StateRepository/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-StateRepository/Operational" ) -or ( $LogPath -match "Microsoft-Windows-StateRepository" ) ){

                                if ( $System.EventID -eq 105 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Informations","PID:"+$System.ProcessID+" ErrorCode:"+$EventData.ErrorCode+" --> "+$EventData.SQL)

                                }

                                if ( $System.EventID -eq 267 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Integrity of referential done","PID:"+$System.ProcessID+" ErrorCode:"+$EventData.SQL+" --> "+$EventData.Filename)

                                }

                            }

                            # Microsoft-Windows-StorageSpaces-Driver/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-StorageSpaces-Driver/Operational" ) -or ( $LogPath -match "Microsoft-Windows-StorageSpaces-Driver" ) ){

                                if ( $System.EventID -eq 207 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Physical disk arrived",$EventData.DriveModel+" --> "+$EventData.DriveSerial)

                                }

                            }

                            if ( ( $LogSearch -eq "Microsoft-Windows-Storage-Storport/Operational" ) -or ( $LogPath -match "Storage-Storport" ) ){

                                # Device was surprise removed
                                if ( $System.EventID -eq 551 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device was removed","("+$EventData.MiniportName+" Port "+$EventData.PortNumber+") "+$EventData.VendorId.Replace(" ","")+" "+$EventData.ProductId.Replace(" ","")+" - "+$EventData.SerialNumber.Replace(" ",""))

                                }

                                # Device has arrived
                                if ( $System.EventID -eq 552 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Device has arrived","("+$EventData.MiniportName+" Port "+$EventData.PortNumber+") "+$EventData.VendorId.Replace(" ","")+" "+$EventData.ProductId.Replace(" ","")+" - "+$EventData.SerialNumber.Replace(" ",""))

                                }

                            }

                            # Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" ) -or ( $LogPath -match "Microsoft-Windows-TerminalServices-LocalSessionManager" ) ){

                                # Session opened successfully
                                if ( $System.EventID -eq 21 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Session opened successfully","("+$UserData.User+") SessionID:"+$UserData.SessionID+" --> "+$UserData.Address)

                                }

                                # Session closed successfully
                                if ( $System.EventID -eq 23 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Session closed successfully","("+$UserData.User+") SessionID:"+$UserData.SessionID)

                                }

                                # Session disconnected successfully
                                if ( $System.EventID -eq 24 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Session disconnected successfully","("+$UserData.User+") SessionID:"+$UserData.SessionID+" --> "+$UserData.Address)

                                }

                                # Session reconnected successfully
                                if ( $System.EventID -eq 25 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Session reconnected successfully","("+$UserData.User+") SessionID:"+$UserData.SessionID+" --> "+$UserData.Address)

                                }

                            }

                            # Microsoft-Windows-TerminalServices-RDPClient/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-TerminalServices-RDPClient/Operational" ) -or ( $LogPath -match "Microsoft-Windows-TerminalServices-RDPClient" ) ){

                                if ( $System.EventID -eq 1024 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RDPClient connexion attempt",$EventData.Name+" --> "+$EventData.Value)

                                }

                                # TODO : Connexion successfull only ?
                                if ( $System.EventID -eq 1027 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RDPClient valid domain ?","SessionId:"+$EventData.SessionId+" --> "+$EventData.DomainName)

                                }

                                # TODO : Connexion successfull only ?
                                if ( $System.EventID -eq 1102 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RDPClient valid Address ?",$EventData.Name+" --> "+$EventData.Value)

                                }

                            }

                            # Microsoft-Windows-Time-Service/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Time-Service/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Time-Service" ) ){

                                if ( $System.EventID -eq 261 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Time has been set",$EventData.OldTime+" --> "+$EventData.NewTime)

                                }

                                if ( $System.EventID -eq 264 ){

                                    $AllNtpServersStr =  (($EventData.AllNtpServers).Replace(";","")).Replace(","," - ")
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Time server accessibility change","NtpServers:"+$AllNtpServersStr)

                                }

                            }

                            # Microsoft-Windows-User Device Registration/Admin
                            if ( ( $LogSearch -eq "Microsoft-Windows-User Device Registration/Admin" ) -or ( $LogPath -match "Microsoft-Windows-User Device Registration" ) ){

                                if ( $System.EventID -eq 101 ){

                                    $ServerMessageJson = ConvertFrom-Json $EventData.ServerMessage
                                    $ServerMessageStr = "Tenant:"+$ServerMessageJson.TenantInfo.TenantId+"/"+$ServerMessageJson.TenantInfo.TenantName+" --> "+$ServerMessageJson.DeviceManagementService.DeviceManagementResourceId
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Discovery callback was successful","PID:"+$System.ProcessID+" "+$ServerMessageStr)

                                }

                                if ( $System.EventID -eq 104 ){

                                    $ServerResponseJson = ConvertFrom-Json $EventData.ServerResponse
                                    $ServerResponseStr = "User:"+$ServerResponseJson.User.Upn
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Join response callback was successful",$ServerResponseStr)

                                }

                            }

                            # Microsoft-Windows-User Profile Service/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-User Profile Service/Operational" ) -or ( $LogPath -match "Microsoft-Windows-User Profile Service" ) ){

                                if ( $System.EventID -eq 5 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"User Profile hive loading","PID:"+$System.ProcessID+" File:"+$EventData.File+" --> "+$EventData.Key)

                                }

                                if ( $System.EventID -eq 67 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"User Profile type","PID:"+$System.ProcessID+" LocalPath:"+$EventData.LocalPath+" LogonType:"+$EventData.LogonType+" ProfileType:"+$EventData.ProfileType)

                                }

                            }

                            # Microsoft-Windows-VHDMP-Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-VHDMP-Operational" ) -or ( $LogPath -match "Microsoft-Windows-VHDMP-Operational" ) ){

                                if ( $System.EventID -eq 1 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Virtual Disk load","PID:"+$System.ProcessID+" VhdDiskNumber:"+$EventData.VhdDiskNumber+" --> "+$EventData.VhdFileName)

                                }

                                if ( $System.EventID -eq 2 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Virtual disk unload","PID:"+$System.ProcessID+" VhdDiskNumber:"+$EventData.VhdDiskNumber+" --> "+$EventData.VhdFileName)

                                }

                            }

                            # Microsoft-Windows-WER-PayloadHealth/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-WER-PayloadHealth/Operational" ) -or ( $LogPath -match "Microsoft-Windows-WER-PayloadHealth" ) ){

                                if ( $System.EventID -eq 1 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wer payload health upload","PID:"+$System.ProcessID+" Protocol:"+$EventData.Protocol+" Stage:"+$EventData.Stage+" --> "+$EventData.ServerName+" ("+$EventData.BytesUploaded+"/"+$EventData.PayloadSize+")")

                                }

                            }

                            # Microsoft-Windows-Win32k/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Win32k/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Win32k" ) ){

                                if ( $System.EventID -eq 260 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Font load attempt","PID:"+$System.ProcessID+" Blocked:"+$EventData.Blocked+" "+$EventData.SourceProcessName+" --> "+$EventData.FontSourcePath)

                                }

                            }

                            # Microsoft-Windows-Windows Defender/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-Windows Defender/Operational" ) -or ( $LogPath -match "Microsoft-Windows-Windows Defender" ) ){

                                if ( $System.EventID -eq 1009 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Defender Restore from Quarantaine","("+$EventData.Domain+"\"+$EventData.User+") "+$EventData."Threat Name"+" --> "+$EventData.Path)

                                }

                                if ( $System.EventID -eq 1011 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Defender Suppress from Quarantaine","("+$EventData.Domain+"\"+$EventData.User+") "+$EventData."Threat Name"+" --> "+$EventData.Path)

                                }

                                if ( $System.EventID -eq 1013 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Defender History Deleted","("+$EventData.Domain+"\"+$EventData.User+") "+$EventData.Timestamp)

                                }

                                if ( $System.EventID -eq 1116 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Defender Threat Detection","("+$EventData."Detection User"+" --> "+$EventData."Process Name"+") "+$EventData."Threat Name"+" --> "+$EventData.Path)

                                }

                                if ( $System.EventID -eq 1117 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Defender Action : "+$EventData."Action Name","("+$EventData."Detection User"+" --> "+$EventData."Process Name"+") "+$EventData."Threat Name"+" --> "+$EventData.Path)

                                }

                            }

                            # Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
                            if ( ( $LogSearch -eq "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" ) -or ( $LogPath -match "Microsoft-Windows-Windows Firewall" ) ){

                                # WARNING : RuleName is inconsistant between the EventIDs in this Log

                                # A rule has been added to the exception list of the firewall
                                if ( $System.EventID -eq 2004 ){

                                    switch ( $EventData.Direction ) {
                                        1 { $DirectionStr = "Incoming" }
                                        2 { $DirectionStr = "Outgoing" }
                                    }
                                    # TODO : If ModifyingApplication -eq "C:\\Windows\\System32\\netsh.exe" --> Suspicious ???
                                    # TODO : Mapping of $EventData.RuleId <--> $EventData.RuleName ( Real Name in MMC ) 
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Firewall rule created","RuleId:"+$EventData.RuleId+" User:"+$EventData.ModifyingUser+" Protocol:"+(FirewallProtocol $EventData.Protocol)+" Local ("+(ShowIfAll $EventData.LocalAddresses)+":"+(ShowIfAll $EventData.LocalPorts)+") Remote ("+(ShowIfAll $EventData.RemoteAddresses)+":"+(ShowIfAll $EventData.RemotePorts)+") "+$EventData.ModifyingApplication+" --> "+$EventData.ApplicationPath)

                                }

                                # A rule was changed in the exception list of the firewall
                                if ( $System.EventID -eq 2005 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Firewall rule changed","RuleId:"+$EventData.RuleId+" User:"+$EventData.ModifyingUser+" Protocol:"+(FirewallProtocol $EventData.Protocol)+" Local ("+(ShowIfAll $EventData.LocalAddresses)+":"+(ShowIfAll $EventData.LocalPorts)+") Remote ("+(ShowIfAll $EventData.RemoteAddresses)+":"+(ShowIfAll $EventData.RemotePorts)+") "+$EventData.ModifyingApplication+" --> "+$EventData.ApplicationPath)

                                }

                                # A rule has been deleted in the exception list of the firewall
                                if ( $System.EventID -eq 2006 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Firewall rule deleted","RuleId:"+$EventData.RuleId+" User:"+$EventData.ModifyingUser+" "+$EventData.ModifyingApplication)

                                }

                                # Network profile has changed on interface
                                if ( $System.EventID -eq 2010 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network profile changed","OldProfile:"+(FirewallProfile $EventData.OldProfile)+" NewProfile:"+(FirewallProfile $EventData.NewProfile)+" InterfaceName:"+$EventData.InterfaceName)

                                }

                                # Firewall was not able to notify user that he refused enterring connexion for an applicaion
                                if ( $System.EventID -eq 2011 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Inbound connexion refused","PId:"+$EventData.ProcessId+" ModifyingUser:"+$EventData.ModifyingUser+" Protocol:"+(FirewallProtocol $EventData.Protocol)+" Port:"+$EventData.Port+" --> "+$EventData.ApplicationPath)

                                }

                            }

                            # Microsoft-Windows-WindowsUpdateClient/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-WindowsUpdateClient/Operational" ) -or ( $LogPath -match "Microsoft-Windows-WindowsUpdateClient" ) ){

                                if ( $System.EventID -eq 25 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WindowsUpdate : An error occured while download","PID:"+$System.ProcessID+" errorCode:"+$EventData.errorCode)

                                }

                                if ( $System.EventID -eq 26 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WindowsUpdate : found update(s)","PID:"+$System.ProcessID+" updateCount:"+$EventData.updateCount)

                                }

                                if ( $System.EventID -eq 31 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WindowsUpdate : failed to download an update","PID:"+$System.ProcessID+" errorCode:"+$EventData.errorCode+" updateRevisionNumber:"+$EventData.updateRevisionNumber+" --> "+$EventData.updateTitle)

                                }

                                if ( $System.EventID -eq 41 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WindowsUpdate : update download","PID:"+$System.ProcessID+" updateRevisionNumber:"+$EventData.updateRevisionNumber+" --> "+$EventData.updateTitle)

                                }

                            }

                            # Microsoft-Windows-WLAN-AutoConfig/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-WLAN-AutoConfig/Operational" ) -or ( $LogPath -match "Microsoft-Windows-WLAN-AutoConfig" ) ){

                                if ( $System.EventID -eq 8000 ){

                                    if ( $EventData.SSID -eq $EventData.ProfileName ) {
                                        $SSIDTypeStr = "Client"
                                    } else {
                                        $SSIDTypeStr = "Access Point"
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi "+$SSIDTypeStr+" connexion started","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID)

                                }

                                if ( $System.EventID -eq 8001 ){

                                    if ( $EventData.SSID -eq $EventData.ProfileName ) {
                                        $SSIDTypeStr = "Client"
                                    } else {
                                        $SSIDTypeStr = "Access Point"
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi "+$SSIDTypeStr+" connected","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID+" Auth:"+$EventData.AuthenticationAlgorithm+"/"+$EventData.CipherAlgorithm)

                                }

                                if ( $System.EventID -eq 8002 ){

                                    if ( $EventData.SSID -eq $EventData.ProfileName ) {
                                        $SSIDTypeStr = "Client"
                                    } else {
                                        $SSIDTypeStr = "Access Point"
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi "+$SSIDTypeStr+" connexion failure","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID+" --> "+$EventData.FailureReason)

                                }

                                if ( $System.EventID -eq 8003 ){

                                    if ( $EventData.SSID -eq $EventData.ProfileName ) {
                                        $SSIDTypeStr = "Client"
                                    } else {
                                        $SSIDTypeStr = "Access Point"
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi "+$SSIDTypeStr+" disconnected","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID+" --> "+$EventData.Reason)

                                }

                                if ( $System.EventID -eq 20019 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi Access Point associated client","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID+"("+$EventData.LocalMAC+") --> PeerMAC:"+$EventData.PeerMAC)

                                }

                                if ( $System.EventID -eq 20021 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Wifi Access Point client failed auth","PID:"+$System.ProcessID+" SSID:"+$EventData.SSID+"("+$EventData.LocalMAC+") --> "+$EventData.ErrorMsg)

                                }

                            }

                            # Microsoft-Windows-WPD-MTPClassDriver/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-WPD-MTPClassDriver/Operational" ) -or ( $LogPath -match "Microsoft-Windows-WPD-MTPClassDriver" ) ){

                                if ( $System.EventID -eq 1005 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"MTP driver configured","PID:"+$System.ProcessID+" Manufacturer:"+$EventData.Manufacturer+" Model:"+$EventData.Model+" Version:"+$EventData.Version)

                                }

                            }

                            # Microsoft-Windows-WMI-Activity/Operational
                            if ( ( $LogSearch -eq "Microsoft-Windows-WMI-Activity/Operational" ) -or ( $LogPath -match "Microsoft-Windows-WMI-Activity" ) ){

                                if ( $System.EventID -eq 5857 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Provider has started","PID:"+$UserData.ProcessID+" Code:"+$UserData.Code+" Name:"+$UserData.ProviderName+" - "+$UserData.HostProcess+" --> "+$UserData.ProviderPath)

                                }

#                                if ( $System.EventID -eq 5858 ){
#
#                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Provider error : "+$UserData.PossibleCause,"("+$UserData.User+") PId:"+$UserData.ClientProcessId+" "+$UserData.ClientMachine+" --> "+$UserData.Operation)
#
#                                }

                                if ( $System.EventID -eq 5859 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Provider request : "+$UserData.PossibleCause,"("+$UserData.User+") PId:"+$UserData.Processid+" "+$UserData.Provider+" - "+$UserData.NamespaceName+" --> "+$UserData.Query)

                                }

                                if ( $System.EventID -eq 5860 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Provider request : "+$UserData.PossibleCause,"("+$UserData.User+") PId:"+$UserData.Processid+" "+$UserData.ClientMachine+" - "+$UserData.NamespaceName+" --> "+$UserData.Query)

                                }

                            }

                            # Setup Log processing
                            if ( ( $LogSearch -eq "Setup" ) -or ( $LogPath -match "Setup" ) ){

                                if ( $System.EventID -eq 4 ){

                                    if ( $UserData.ErrorCode -eq "0x0" ) { $ErrorCodeStr = "Success" } else { $ErrorCodeStr = "Error "+$UserData.ErrorCode }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Security Update","PId:"+$System.ProcessID+" Component:"+$UserData.Client+" Update:"+$UserData.PackageIdentifier+" Result:"+$ErrorCodeStr)

                                }

                            }

                            # Security Log processing
                            if ( ( $LogSearch -eq "Security" ) -or ( $LogPath -match "Security" ) ){

                                Write-Debug "[+] Security Log matched"

                                # The audit log was cleared
                                if ( $System.EventID -eq 1102 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The audit log was cleared","("+$UserData.SubjectDomainName+"\"+$UserData.SubjectUserName+") PId:"+$System.ProcessID)

                                }

                                # An authentication package has been loaded by the Local Security Authority
                                if ( $System.EventID -eq 4610 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Lsass loaded an auth package","PId:"+$System.ProcessID+" "+$EventData.AuthenticationPackageName)

                                }

                                # A trusted logon process has been registered with the Local Security Authority
                                if ( $System.EventID -eq 4611 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Lsass registered a trusted logon process","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+$System.ProcessID+" "+$EventData.LogonProcessName)

                                }

                                # A notification package has been loaded by the Security Account Manager
                                if ( $System.EventID -eq 4614 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Sam loaded a notification package","PId:"+$System.ProcessID+" "+$EventData.NotificationPackageName)

                                }

                                # The system time was changed
                                if ( $System.EventID -eq 4616 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The system time was changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+$System.ProcessId+" "+$EventData.ProcessName+" - "+$EventData.PreviousTime+" --> "+$EventData.NewTime)

                                }

                                # A security package has been loaded by the Local Security Authority
                                if ( $System.EventID -eq 4622 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Lsass loaded a security package","PId:"+$System.ProcessID+" "+$EventData.SecurityPackageName)

                                }

                                # An account was successfully logged on
                                if ( $System.EventID -eq 4624 ){

                                    switch ( $EventData.ElevatedToken ) {
                                        "%%1842" { $TokenStr = "An Admin" }
                                        "%%1843" { $TokenStr = "A  User " }
                                    }
                                    # Exclude LogonType = 0
                                    if ( $EventData.LogonType -ne 0 ) {
                                        [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : "+$TokenStr+" account was successfully logged on","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" LogonType:"+$EventData.LogonType+" Auth:"+$EventData.AuthenticationPackageName+" Logon:"+$EventData.LogonProcessName+" --> "+$EventData.IpAddress+":"+$EventData.IpPort)
                                    }

                                }

                                # An account failed to log on
                                if ( $System.EventID -eq 4625 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : An account failed to log on","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") PId:"+[uint32]$System.ProcessId+" "+$EventData.ProcessName+" LogonType:"+$EventData.LogonType+" Auth:"+$EventData.AuthenticationPackageName+" Logon:"+$EventData.LogonProcessName+" --> "+$EventData.IpAddress+":"+$EventData.IpPort)

                                }

                                # An account was logged off
                                if ( $System.EventID -eq 4634 ){

                                    # TODO : User <--> UserSid mapping : $EventData.TargetDomainName+"\"+$EventData.TargetUserName+" <--> "+$EventData.TargetUserSid
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : An account was logged off","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") LogonType:"+$EventData.LogonType)

                                }

                                # A logon was attempted using explicit credentials
                                if ( $System.EventID -eq 4648 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Logon attempted with explicit credentials","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> "+$EventData.TargetServerName+" ("+$EventData.IpAddress+":"+$EventData.IpPort+")")

                                }

                                # A handle to an object was requested
                                if ( $System.EventID -eq 4656 ){

                                    # TODO: Generate such event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A handle to an object was requested","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" HandleId:"+$EventData.HandleId+" "+$EventData.ProcessName+" --> "+$EventData.ObjectName)

                                }

                                # A registry value was modified
                                if ( $System.EventID -eq 4657 ){

                                    # TODO: Generate such event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A registry value was modified",$System.ProcessID+";"+$EventData.OperationType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.ObjectValueName+";"+$EventData.ObjectName+";"+$EventData.OldValue+";"+$EventData.NewValue)

                                }

                                # The handle to an object was closed
                                if ( $System.EventID -eq 4658 ){

                                    # TODO: Generate such event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The handle to an object was closed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" HandleId:"+$EventData.HandleId+" "+$EventData.ProcessName)

                                }

                                # An object was deleted
                                if ( $System.EventID -eq 4660 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : An object was deleted","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> "+$EventData.ObjectServer+" : "+$EventData.HandleId)

                                }

                                # An operation was performed on an object
                                if ( $System.EventID -eq 4662 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Operation performed on an object","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+$System.ProcessID+" "+$EventData.ObjectServer+" "+$EventData.OperationType+" --> "+$EventData.ObjectType+" "+$EventData.ObjectName+" "+$EventData.AdditionalInfo+" "+$EventData.AdditionalInfo2)

                                }

                                # An attempt was made to access an object
                                if ( $System.EventID -eq 4663 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : An attempt was made to access an object","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> "+$EventData.ObjectServer+" "+$EventData.ObjectType+" : "+$EventData.ObjectName)

                                }

                                # Permissions on an object were changed
                                if ( $System.EventID -eq 4670 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Permissions on an object were changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ObjectServer+" "+$EventData.ObjectType+" "+$EventData.ProcessName+" "+$EventData.ObjectName+" "+$EventData.OldSd+" --> "+$EventData.NewSd)

                                }

                                # Special privileges assigned to new logon
                                if ( $System.EventID -eq 4672 ){

                                    $PrivilegeListStr = ($EventData.PrivilegeList).Replace("\n\t\t\t","/")
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Special privileges assigned to new logon","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+$System.ProcessID+" "+$PrivilegeListStr)

                                }

                                # A privileged service was called
                                if ( $System.EventID -eq 4673 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A privileged service was called","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> "+$EventData.ObjectServer+" "+$EventData.Service+" "+$EventData.PrivilegeList)

                                }

                                # An operation was attempted on a privileged object
                                if ( $System.EventID -eq 4674 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : An operation was attempted on a privileged object","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> "+$EventData.ObjectServer+" "+$EventData.PrivilegeList)

                                }

                                # A new process has been created
                                if ( $System.EventID -eq 4688 ){

                                    if ( $null -ne $EventData.CommandLine ) {
                                        $ProcessInfo = $EventData.CommandLine
                                    }else{
                                        $ProcessInfo = $EventData.NewProcessName
                                    }
                                    if ( $EventData.TargetDomainName."\".$EventData.TargetUserName -ne "-/-" ) {
                                        [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A new process has been created","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ParentProcessName+" --> ("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") "+[uint32]$EventData.NewProcessId+" "+$ProcessInfo)

                                    } else {
                                        [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A new process has been created","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ParentProcessName+" --> "+[uint32]$EventData.NewProcessId+" "+$ProcessInfo)
                                    }

                                }

                                # A process has exited
                                if ( $System.EventID -eq 4689 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A process has exited","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName)

                                }

                                # An attempt was made to duplicate a handle to an object
                                if ( $System.EventID -eq 4690 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : handle duplication attempt","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.SourceProcessId+" SourceHandleId:"+$EventData.SourceHandleId+" --> "+[uint32]$EventData.TargetProcessId+" TargetHandleId:"+$EventData.TargetHandleId)

                                }

                                # A primary token was assigned to process
                                if ( $System.EventID -eq 4696 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A primary token was assigned to process","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ProcessId+" "+$EventData.ProcessName+" --> ("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") TPId:"+[UInt32]$EventData.TargetProcessId+" "+$EventData.TargetProcessName)

                                }

                                # A service was installed in the system
                                if ( $System.EventID -eq 4697 ){
                                    # Find more well known services
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A service was installed in the system","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" Name:"+$EventData.ServiceName+" Type:"+$EventData.ServiceType+" Account:"+$EventData.ServiceAccount+" Start:"+$EventData.ServiceStartType+" "+$EventData.ServiceFileName)

                                }

                                # A scheduled task was created
                                if ( $System.EventID -eq 4698 ){

                                    $TaskContentXML = [Xml]$EventData.TaskContent
                                    $SchedTaskAction = $TaskContentXML.Task.Actions.Exec.Command+" "+$TaskContentXML.Task.Actions.Exec.Arguments
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A scheduled task was created","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" "+$EventData.TaskName+" --> "+$SchedTaskAction)

                                }

                                # A scheduled task was deleted
                                if ( $System.EventID -eq 4699 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A scheduled task was deleted","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" "+$EventData.TaskName)

                                }

                                # A scheduled task was enabled
                                if ( $System.EventID -eq 4700 ){

                                    # TODO : Generate such event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A scheduled task was enabled","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" "+$EventData.TaskName)

                                }

                                # A scheduled task was disabled
                                if ( $System.EventID -eq 4701 ){

                                    # TODO : Generate such event
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A scheduled task was disabled","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" "+$EventData.TaskName)

                                }

                                # A scheduled task was updated
                                if ( $System.EventID -eq 4702 ){

                                    $TaskContentXML = [Xml]$EventData.TaskContentNew
                                    if ( $null -ne $TaskContentXML.Task.Actions.Exec ) {
                                        # <Actions Context="LocalSystem">
                                        #   <Exec>
                                        #     <Command>%windir%\system32\sc.exe</Command>
                                        #     <Arguments>start pushtoinstall registration</Arguments>
                                        #   </Exec>
                                        # </Actions>
                                        $SchedTaskAction = "CommandLine: "+$TaskContentXML.Task.Actions.Exec.Command+" "+$TaskContentXML.Task.Actions.Exec.Arguments
                                    } else {
                                        # <Actions Context="LocalSystem">
                                        #   <ComHandler>
                                        #     <ClassId>{47E30D54-DAC1-473A-AFF7-2355BF78881F}</ClassId>
                                        #     <Data><![CDATA[NGCKeyPregen]]></Data>
                                        #   </ComHandler>
                                        # </Actions>
                                        $SchedTaskAction = "ComHandler: "+$TaskContentXML.Task.Actions.ComHandler.ClassId+" "+$TaskContentXML.Task.Actions.ComHandler.Data
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A scheduled task was updated","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PId:"+[uint32]$EventData.ClientProcessId+" "+$EventData.TaskName+" --> "+$SchedTaskAction)

                                }

                                # System audit policy was changed
                                if ( $System.EventID -eq 4719 ){

                                    $SubCategoryStr = AuditSubCategory($EventData.SubcategoryGuid)
                                    if ( ($EventData.AuditPolicyChanges).Split(",").Count -eq 1 ) { 
                                        $AuditPolicyChangesStr = AuditPolicyChanges($EventData.AuditPolicyChanges)
                                    } else {
                                        $i = 0
                                        ForEach ( $AuditPolicyChange in ($EventData.AuditPolicyChanges).Split(",") ) {
                                            if ( $i -eq 0 ) {
                                                $AuditPolicyChangesStr = AuditPolicyChanges($AuditPolicyChange)
                                                $i++
                                            } else {
                                                $AuditPolicyChangesStr += ", "
                                                $AuditPolicyChangesStr += AuditPolicyChanges($AuditPolicyChange)
                                            }
                                        }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : System audit policy was changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" Subcategory:"+$SubCategoryStr+" --> "+$AuditPolicyChangesStr)

                                }

                                # A user account was created
                                if ( $System.EventID -eq 4720 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was created","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # A user account was enabled
                                if ( $System.EventID -eq 4722 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was enabled","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # An attempt was made to reset an account's password
                                if ( $System.EventID -eq 4724 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was enabled","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # A user account was disabled
                                if ( $System.EventID -eq 4725 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was enabled","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # A user account was deleted
                                if ( $System.EventID -eq 4726 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was deleted","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # A member was added to a security-enabled global group
                                if ( $System.EventID -eq 4728 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A member added to global group","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+" ("+$EventData.TargetSid+")")

                                }

                                # A member was added to a security-enabled local group
                                if ( $System.EventID -eq 4732 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A member added to local group","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" "+$EventData.MemberSid+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # A member was removed from a security-enabled local group
                                if ( $System.EventID -eq 4733 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A member removed from local group","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" "+$EventData.MemberSid+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # A security-enabled local group was changed
                                if ( $System.EventID -eq 4735 ){
                                    # If SamAccountName SidHistory and PrivilegeList = - other param that are not listed have changed
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" "+$EventData.UserPrincipalName+" "+$EventData.AllowedToDelegateTo+" "+$EventData.SidHistory+" "+$EventData.PrivilegeList+" "+$EventData.PasswordLastSet+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # A user account was changed
                                if ( $System.EventID -eq 4738 ){
                                    # TODO : Detect what changed
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user account was changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" "+$EventData.UserPrincipalName+" "+$EventData.AllowedToDelegateTo+" "+$EventData.SidHistory+" "+$EventData.PrivilegeList+" "+$EventData.PasswordLastSet+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # The computer attempted to validate the credentials for an account
                                if ( $System.EventID -eq 4776 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Computer attempted to validate the credentials for an account","("+$EventData.TargetUserName+") Workstation:"+$EventData.Workstation+" PackageName:"+$EventData.PackageName+" Status:"+$EventData.Status)

                                }

                                # A session was reconnected to a Window Station
                                if ( $System.EventID -eq 4778 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A session was reconnected to a Window Station","("+$EventData.AccountDomain+"\"+$EventData.AccountName+") SessionName:"+$EventData.SessionName+" ClientName:"+$EventData.ClientName+" ClientAddress:"+$EventData.ClientAddress)

                                }

                                # A session was disconnected from a Window Station
                                if ( $System.EventID -eq 4779 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A session was reconnected to a Window Station","("+$EventData.AccountDomain+"\"+$EventData.AccountName+") SessionName:"+$EventData.SessionName+" ClientName:"+$EventData.ClientName+" ClientAddress:"+$EventData.ClientAddress)

                                }

                                # The name of an account was changed
                                if ( $System.EventID -eq 4781 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The name of an account was changed","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+[uint32]$System.ProcessID+" "+$EventData.TargetDomainName+"\"+$EventData.OldTargetUserName+" --> "+$EventData.TargetDomainName+"\"+$EventData.NewTargetUserName)

                                }

                                # A user's local group membership was enumerated
                                if ( $System.EventID -eq 4798 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user's local group membership was enumerated","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") CallerPId:"+[uint32]$EventData.CallerProcessId+" "+$EventData.CallerProcessName+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # A security-enabled local group membership was enumerated
                                if ( $System.EventID -eq 4799 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : A user's local group membership was enumerated","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") CallerPId:"+[uint32]$EventData.CallerProcessId+" "+$EventData.CallerProcessName+" --> "+$EventData.TargetDomainName+"\"+$EventData.TargetUserName)

                                }

                                # The workstation was locked
                                if ( $System.EventID -eq 4800 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The workstation was locked","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") SessionId:"+$EventData.SessionId)

                                }

                                # The workstation was unlocked
                                if ( $System.EventID -eq 4801 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The workstation was unlocked","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") SessionId:"+$EventData.SessionId)

                                }

                                # The screen saver was invoked
                                if ( $System.EventID -eq 4802 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The screen saver was invoked","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") SessionId:"+$EventData.SessionId)

                                }

                                # The screen saver was dismissed
                                if ( $System.EventID -eq 4803 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : The screen saver was dismissed","("+$EventData.TargetDomainName+"\"+$EventData.TargetUserName+") SessionId:"+$EventData.SessionId)

                                }

                                # Key file operation
                                if ( $System.EventID -eq 5058 ){
                                    # Operation needs human traduction
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Key file operation","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") ClientPId:"+$EventData.ClientProcessId+" KeyName:"+$EventData.KeyName+" KeyFilePath:"+$EventData.KeyFilePath)

                                }

                                # Key migration operation
                                if ( $System.EventID -eq 5059 ){
                                    # Operation needs human traduction
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Key migration operation","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") ClientPId:"+$EventData.ClientProcessId+" KeyName:"+$EventData.KeyName+" AlgorithmName:"+$EventData.AlgorithmName)

                                }

                                # Cryptographic operation
                                if ( $System.EventID -eq 5061 ){
                                    # Operation needs human traduction
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Cryptographic operation","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") PID:"+$System.ProcessID+" KeyName:"+$EventData.KeyName+" AlgorithmName:"+$EventData.AlgorithmName)

                                }

                                # A network share object was checked to see whether client can be granted desired access.
                                if ( $System.EventID -eq 5145 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Acces granted to a network share object","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") ClientPId:"+$EventData.ProcessID+" ObjectType:"+$EventData.ObjectType+" From:"+$EventData.IpAddress+":"+$EventData.IpPort+" --> "+$EventData.ShareName+$EventData.ShareLocalPath+" ("+$EventData.RelativeTargetName+")")

                                }

                                # The Windows Filtering Platform has permitted a connection
                                if ( $System.EventID -eq 5156 ){

                                    switch ( $EventData.Direction ) {
                                        "%%14592" { $DirectionStr = "Inbound" }
                                        "%%14593" { $DirectionStr = "Outbound" }
                                    }
                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Filtering Platform permitted a connection","PId:"+$EventData.ProcessId+" "+$EventData.Application+" "+$DirectionStr+" "+$EventData.Protocol+" "+$EventData.SourceAddress+":"+$EventData.SourcePort+" --> "+$EventData.DestAddress+":"+$EventData.DestPort)

                                }

                                # The Windows Filtering Platform has permitted a bind to a local port
                                if ( $System.EventID -eq 5158 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Filtering Platform permitted a bind to a local port","PId:"+$EventData.ProcessId+" "+$EventData.Application+" "+$EventData.Protocol+" "+$EventData.SourceAddress+":"+$EventData.SourcePort)

                                }

                                # Credential Manager credentials were read
                                if ( $System.EventID -eq 5379 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,$System.EventID+" : Credential Manager credentials were read","("+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+") ClientPId:"+$EventData.ClientProcessId+" "+$EventData.ProcessCreationTime+" TargetName:"+$EventData.TargetName+" Count:"+$EventData.CountOfCredentialsReturned)

                                }

                            }

                            if ( ( $LogSearch -match "Sysmon" ) -or ( $LogPath -match "Sysmon" ) ){

                                # Process Create
                                if ( $System.EventID -eq 1 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Process Create","("+$EventData.User+") PPId:"+$EventData.ParentProcessId+" "+$EventData.ParentCommandLine+" --> PId:"+$EventData.ProcessId+" "+$EventData.CommandLine)

                                }

                                # File creation time changed
                                if ( $System.EventID -eq 2 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File creation time changed","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetFileName+" Newdate : "+$EventData.CreationUtcTime+" Olddate : "+$EventData.PreviousCreationUtcTime)

                                }

                                # Network connection detected
                                if ( $System.EventID -eq 3 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Network connection detected","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" : "+$EventData.Protocol+" - "+$EventData.SourceIp+":"+$EventData.SourcePort+" --> "+$EventData.DestinationIp+":"+$EventData.DestinationPort)

                                }

                                # Sysmon service state changed
                                if ( $System.EventID -eq 4 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Sysmon service state changed",$EventData.State+" : Schema "+$EventData.SchemaVersion+" - Version "+$EventData.Version)

                                }

                                # Process terminated
                                if ( $System.EventID -eq 5 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Process terminated","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image)

                                }

                                # Driver loaded into kernel
                                if ( $System.EventID -eq 6 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Driver loaded",$EventData.ImageLoaded+" - "+$EventData.Signature+" - "+$EventData.SignatureStatus+" - "+$EventData.Signed+" - "+$EventData.Hashes)

                                }

                                # Image loaded
                                if ( $System.EventID -eq 7 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Image loaded","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.ImageLoaded+" - "+$EventData.Signature+" - "+$EventData.SignatureStatus+" - "+$EventData.Signed+" - "+$EventData.Hashes)

                                }

                                # CreateRemoteThread detected
                                if ( $System.EventID -eq 8 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"CreateRemoteThread detected","("+$EventData.SourceUser+") SPId:"+$EventData.SourceProcessId+" "+$EventData.SourceImage+" --> ("+$EventData.TargetUser+") TPId:"+$EventData.TargetProcessId+" "+$EventData.TargetImage+" - "+$EventData.StartAddress+" - "+$EventData.StartModule+" - "+$EventData.StartFunction)

                                }

                                # RawAccessRead detected
                                if ( $System.EventID -eq 9 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RawAccessRead detected","("+$EventData.SourceUser+") PId:"+$EventData.SourceProcessId+" "+$EventData.SourceImage+" --> "+$EventData.TargetUser+") PID:"+$EventData.TargetProcessId+" "+$EventData.TargetImage+" - "+$EventData.StartAddress+" - "+$EventData.StartModule+" - "+$EventData.StartFunction)

                                }

                                # Process accessed
                                if ( $System.EventID -eq 10 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Process accessed","("+$EventData.SourceUser+") PId:"+$EventData.SourceProcessId+" "+$EventData.SourceImage+" --> ("+$EventData.TargetUser+") PId:"+$EventData.TargetProcessId+" "+$EventData.TargetImage)

                                }

                                # File created
                                if ( $System.EventID -eq 11 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File created","("+$EventData.CreationUtcTime+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetFileName)

                                }

                                # RegistryEvent - Registry object added or deleted
                                if ( $System.EventID -eq 12 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RegistryEvent : "+$EventData.EventType,"PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetObject)

                                }

                                # RegistryEvent - Registry value set
                                if ( $System.EventID -eq 13 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RegistryEvent : "+$EventData.EventType,"PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetObject+" - "+$EventData.Details)

                                }

                                # RegistryEvent - Registry object renamed
                                if ( $System.EventID -eq 14 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"RegistryEvent"+$EventData.EventType,"("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetObject+" - "+$EventData.NewName)

                                }

                                # File stream created
                                if ( $System.EventID -eq 15 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File stream created","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetFileName+" - "+$EventData.Contents)

                                }

                                # Sysmon config state changed
                                if ( $System.EventID -eq 16 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Sysmon config state changed",$EventData.Configuration+" - "+$EventData.ConfigurationFileHash+" - "+$EventData.UtcTime)

                                }

                                # PipeEvent - Pipe Created
                                if ( $System.EventID -eq 17 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"PipeEvent : "+$EventData.EventType,"("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.PipeName)

                                }

                                # PipeEvent - Pipe Connected
                                if ( $System.EventID -eq 18 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"PipeEvent : "+$EventData.EventType,"("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.PipeName)

                                }

                                # WmiEvent - WmiEventFilter activity detected
                                if ( $System.EventID -eq 19 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WmiEvent : "+$EventData.EventType,"("+$EventData.User+") "+$EventData.Operation+" : "+$EventData.Name+" - "+$EventData.EventNameSpace+" - "+$EventData.Query)

                                }

                                # WmiEvent - WmiEventConsumer activity detected
                                if ( $System.EventID -eq 20 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WmiEvent : "+$EventData.EventType,"("+$EventData.User+") "+$EventData.Operation+" : "+$EventData.Name+" - "+$EventData."Type"+" - "+$EventData.Destionation)

                                }

                                # WmiEvent - WmiEventConsumerToFilter activity detected
                                if ( $System.EventID -eq 21 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"WmiEvent : "+$EventData.EventType,"("+$EventData.User+") "+$EventData.Operation+" : "+$EventData.Name+" - "+$EventData.Consumer+" - "+$EventData."Filter")

                                }

                                # Dns query
                                if ( $System.EventID -eq 22 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Dns query","PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> Query : "+$EventData.QueryName+" - Result : "+$EventData.QueryResults)

                                }

                                # File Delete
                                if ( $System.EventID -eq 23 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File Delete","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetFileName+" - "+$EventData.Hashes)

                                }

                                # Clipboard changed
                                if ( $System.EventID -eq 24 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Clipboard changed","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.Session+" - "+$EventData.ClientInfo+" - "+$EventData.Hashes)

                                }

                                # Process Tampering
                                if ( $System.EventID -eq 25 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Process Tampering","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData."Type")

                                }

                                # File Deleted
                                if ( $System.EventID -eq 26 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"File Deleted","("+$EventData.User+") PId:"+$EventData.ProcessId+" "+$EventData.Image+" --> "+$EventData.TargetFileName+" - "+$EventData.Hashes)

                                }

                            }

                            if ( ( $LogSearch -eq "System" ) -or ( $LogPath -match "System.evtx" ) ){

                                # BTHUSB
                                if ( $System.EventID -eq 8 ){

                                    # TODO: Identify what it is, seems to be BTH devices USB Mac Address
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"BTHUSB connection",$EventData.Data1)

                                }

                                # Microsoft-Windows-WindowsUpdateClient
                                if ( $System.EventID -eq 19 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Update successful","Ver:"+$EventData.updateRevisionNumber+" --> "+$EventData.updateTitle)

                                }

                                # Application Popup
                                if ( $System.EventID -eq 26 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Application Popup","PId:"+$System.ProcessID+" "+$EventData.Caption+" --> "+$EventData.Message)

                                }

                                # Microsoft-Windows-WindowsUpdateClient
                                if ( $System.EventID -eq 44 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Update download started","Ver:"+$EventData.updateRevisionNumber+" --> "+$EventData.updateTitle)

                                }

                                # Microsoft-Windows-Ntfs
                                if ( $System.EventID -eq 98 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Volume Mounting : System Start","DriveName:"+$EventData.DriveName+" DeviceName:"+$EventData.DeviceName)

                                }

                                # Microsoft-Windows-Eventlog
                                if ( $System.EventID -eq 104 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"A Log was cleaned : "+$UserData.Channel,"PId:"+$System.ProcessID+" --> "+$UserData.SubjectDomainName+"\"+$UserData.SubjectUserName)

                                }

                                # Microsoft-Windows-DNS-Client
                                if ( $System.EventID -eq 1014 ){

                                    # Find what this queries represant
                                    # TODO : Address conversion
                                    [TimeLine]::New($System.SystemTime,$System.Computer,"DNS Client","PId:"+$System.ProcessID+" "+$EventData.QueryName+" --> "+$EventData.Address)

                                }

                                # Microsoft-Windows-Winlogon
                                if ( $System.EventID -eq 7001 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Winlogon Session : open","UserSid: "+$EventData.UserSid)

                                }

                                # Microsoft-Windows-Winlogon
                                if ( $System.EventID -eq 7002 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Winlogon Session : close","UserSid: "+$EventData.UserSid)

                                }

                                # TODO : 7045 New service was installed

                                # Microsoft-Windows-UserPnp
                                if ( $System.EventID -eq 20001 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Driver Installed ("+$UserData.InstallStatus+")","PId:"+$System.ProcessID+" "+$UserData.DriverProvider+" --> "+$UserData.DeviceInstanceID)

                                }

                                # Microsoft-Windows-UserPnp
                                if ( $System.EventID -eq 20003 ){

                                    [TimeLine]::New($System.SystemTime,$System.Computer,"Driver Service added","PId:"+$System.ProcessID+" "+$UserData.ServiceName+" --> "+$UserData.DriverFileName+" for "+$UserData.DeviceInstanceID)

                                }

                            }

                        } else {

                            Write-Host "System :"
                            $System | ConvertTo-Json
                            if ( $EventData.Count -eq 0 ) {
                                Write-Host "UserData :"
                                $UserData | ConvertTo-Json
                            } else {
                                Write-Host "EventData :"
                                $EventData | ConvertTo-Json
                            }

                        }

                    }
        
                }

            } # End ForEach

        } # End If Event.Count -gt 0

    }

}
