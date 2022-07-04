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


    Write-Host "     _____       _             _____ _ _ _            "
    Write-Host "    | ____|_   _| |___  __    |  ___(_) | |_ ___ _ __ "
    Write-Host "    |  _| \ \ / / __\ \/ /____| |_  | | | __/ _ \ '__|"
    Write-Host "    | |___ \ V /| |_ >  <_____|  _| | | | ||  __/ |   "
    Write-Host "    |_____| \_/  \__/_/\_\    |_|   |_|_|\__\___|_|   "
    Write-Host "                                                      "
    Write-Host "                                           by Croko-fr"
    Write-Host "                                                      "


    ForEach ( $Parameter in $PSBoundParameters.GetEnumerator() ) {

        Switch ( $Parameter.Key ) {

            "ListLog" {
                        Write-Host "[+] Listing computer eventLogs"
                        Get-WinEvent -ListLog * | Select-Object RecordCount,LogName | Where-Object { $_.RecordCount -ne 0 -and $null -ne $_.RecordCount } | Sort-Object RecordCount -Descending
                        break
                        write-Host "break1"
                        break
                    }

            "LogPath" {
                        Try {
                            $null = Test-Path -Path $LogPath -ErrorAction Stop
                            $FullLogPath = Resolve-Path $LogPath 
                            Write-Host "[+] Searching EventLog : $FullLogPath"
                            $XmlQuery = "<QueryList> <Query Id='0' Path='file://$FullLogPath'> <Select Path='file://$FullLogPath'> "
                            $Request = "Get-WinEvent -Path '$FullLogPath'"
                        } Catch {
                            Write-Host "[x] No EventLog found with path : $LogPath"
                            break
                        }
                        break
                    }

            "LogSearch" {
                        $Logs = @(Get-WinEvent -ListLog * | Select-Object RecordCount,LogName | Where-Object { $_.RecordCount -ne 0 -and $null -ne $_.RecordCount } ).LogName 
                        if ( $Logs -match $LogSearch ) {
                            $LogName = @($Logs -match $LogSearch)
                            Write-Host "[+] Searching EventLog : $LogName"
                            $XmlQuery = "<QueryList>`<Query Id='0' Path='$LogName'> <Select Path='$LogName'> "
                            $Request = "Get-WinEvent -LogName $LogName"
                        } Else {
                            Write-Host "[x] No EventLog found with name : $LogSearch"
                            Break
                        }
                        break
                    }

            "RawSearch" {
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
                    if ( ( $null -ne $eventXML.Event.UserData.ChildNodes[$i].'#text' ) -Or ( $eventXML.Event.UserData.ChildNodes[$i].'#text' -ne "NULL" ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "null" ) ) {
                        if ( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name -eq "Data" ) {
                            $UserData.add( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name+$i , $eventXML.Event.UserData.FirstChild.ChildNodes[$i].'#text' )
                        } else {
                            $UserData.add( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name , $eventXML.Event.UserData.FirstChild.ChildNodes[$i].'#text' )
                        }
                    }
                }
                for ($i=0; $i -lt $eventXML.Event.EventData.ChildNodes.Count; $i++) {
                    $LogType = "EventData"
                    if ( ( $null -ne $eventXML.Event.EventData.ChildNodes[$i].'#text' ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "NULL" ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "null" ) ) {
                        if ( $eventXML.Event.EventData.ChildNodes[$i].Name -eq "Data" ) {
                            $EventData.add( $eventXML.Event.EventData.ChildNodes[$i].Name+$i , $eventXML.Event.EventData.ChildNodes[$i].'#text' )
                        } else {
                            $EventData.add( $eventXML.Event.EventData.ChildNodes[$i].Name , $eventXML.Event.EventData.ChildNodes[$i].'#text' )
                        }
                    }
                }

                if ( $PSBoundParameters.ContainsKey('ConvertToSigma') -eq $true ) {

                    $Result = [String]"title: " + $System.Provider_Name + " EventID " + $System.EventID + "`r`n"
                    $Result += "id: " + (New-Guid).Guid + "`r`n"
                    # Find description for known EventID
                    $CatalogFilePath = (Get-Location).Path+"\"+$CatalogFile
                    if ( Test-Path $CatalogFilePath ) {
                        $Match = (( Get-Content $CatalogFilePath ) -match ($System.Provider_Name+";"+$System.EventID+";") ) -split ";"
                        if ( $Match ) {
                            $Description = $Match[2]
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
    
                            if ( ( $null -ne $(Get-Variable "$LogType" -ValueOnly).$Data ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "NULL" ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "null" ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "Null" ) ) {
                                # Add your selection of Keys here
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

                            # Setup Log processing
                            if ( ( $LogSearch -eq "Setup" ) -or ( $LogPath -match "Setup" ) ){

                                if ( $System.EventID -eq 4 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Security Update;"+$System.ProcessID+";"+$UserData.Client+";"+$UserData.PackageIdentifier+";"+$UserData.ErrorCode)

                                }

                            }

                            # Security Log processing
                            if ( ( $LogSearch -eq "Security" ) -or ( $LogPath -match "Security" ) ){

                                # An authentication package has been loaded by the Local Security Authority
                                if ( $System.EventID -eq 4610 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.AuthenticationPackageName)

                                }

                                # A trusted logon process has been registered with the Local Security Authority
                                if ( $System.EventID -eq 4611 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.LogonProcessName+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.SubjectUserSid+";"+$EventData.SubjectLogonId)

                                }

                                # A notification package has been loaded by the Security Account Manager
                                if ( $System.EventID -eq 4614 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.NotificationPackageName)

                                }

                                # A security package has been loaded by the Local Security Authority
                                if ( $System.EventID -eq 4622 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SecurityPackageName)

                                }

                                # An account was successfully logged on
                                if ( $System.EventID -eq 4624 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.AuthenticationPackageName+";"+$EventData.IpAddress+";"+$EventData.IpPort+";"+$EventData.LogonProcessName+";"+$EventData.LogonType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # An account failed to log on
                                if ( $System.EventID -eq 4625 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.AuthenticationPackageName+";"+$EventData.IpAddress+";"+$EventData.IpPort+";"+$EventData.LogonProcessName+";"+$EventData.LogonType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # An account was logged off
                                if ( $System.EventID -eq 4634 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.LogonType+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.TargetUserSid+";"+$EventData.TargetLogonId)

                                }

                                # A logon was attempted using explicit credentials
                                if ( $System.EventID -eq 4648 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.IpAddress+";"+$EventData.IpPort+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.TargetServerName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A handle to an object was requested
                                if ( $System.EventID -eq 4656 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.ObjectServer+";"+$EventData.ObjectType+";"+$EventData.HandleId+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.ObjectName)

                                }

                                # A registry value was modified
                                if ( $System.EventID -eq 4657 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.OperationType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.ObjectValueName+";"+$EventData.ObjectName+";"+$EventData.OldValue+";"+$EventData.NewValue)

                                }

                                # The handle to an object was closed
                                if ( $System.EventID -eq 4658 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.ObjectServer+";"+$EventData.HandleId+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName)

                                }

                                # An object was deleted
                                if ( $System.EventID -eq 4660 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.ObjectServer+";"+$EventData.HandleId+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName)

                                }

                                # An operation was performed on an object
                                if ( $System.EventID -eq 4662 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.OperationType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ObjectServer+";"+$EventData.ObjectType+";"+$EventData.ObjectName+";"+$EventData.AdditionalInfo+";"+$EventData.AdditionalInfo2)

                                }

                                # An attempt was made to access an object
                                if ( $System.EventID -eq 4663 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ObjectServer+";"+$EventData.ObjectType+";"+$EventData.ObjectName+";"+$EventData.ProcessId+";"+$EventData.HandleId+";"+$EventData.ProcessName)

                                }

                                #Permissions on an object were changed
                                if ( $System.EventID -eq 4670 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ObjectServer+";"+$EventData.ObjectType+";"+$EventData.ObjectName+";"+$EventData.ProcessId+";"+$EventData.HandleId+";"+$EventData.ProcessName+";"+$EventData.OldSd+";"+$EventData.NewSd)

                                }

                                # Special privileges assigned to new logon
                                if ( $System.EventID -eq 4672 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.PrivilegeList)

                                }

                                # A privileged service was called
                                if ( $System.EventID -eq 4673 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ObjectServer+";"+$EventData.Service+";"+$EventData.PrivilegeList+";"+$EventData.ProcessId+";"+$EventData.ProcessName)

                                }

                                # An operation was attempted on a privileged object
                                if ( $System.EventID -eq 4674 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ObjectServer+";"+$EventData.ObjectType+";"+$EventData.ObjectName+";"+$EventData.PrivilegeList+";"+$EventData.ProcessId+";"+$EventData.HandleId+";"+$EventData.ProcessName)

                                }

                                # A new process has been created
                                if ( $System.EventID -eq 4688 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ParentProcessName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.NewProcessId+";"+$EventData.NewProcessName+";"+$EventData.CommandLine)

                                }

                                # A process has exited
                                if ( $System.EventID -eq 4689 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.Status)

                                }

                                # An attempt was made to duplicate a handle to an object
                                if ( $System.EventID -eq 4690 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.SourceProcessId+";"+$EventData.SourceHandleId+";"+$EventData.TargetProcessId+";"+$EventData.TargetHandleId)

                                }

                                # A primary token was assigned to process
                                if ( $System.EventID -eq 4696 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessId+";"+$EventData.ProcessName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.TargetProcessId+";"+$EventData.TargetProcessName)

                                }

                                # A service was installed in the system
                                if ( $System.EventID -eq 4697 ){
                                    # Find more well known services
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ServiceName+";"+$EventData.ServiceType+";"+$EventData.ServiceAccount+";"+$EventData.ServiceStartType+";"+$EventData.ServiceFileName)

                                }

                                # A scheduled task was created
                                if ( $System.EventID -eq 4698 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TaskName)

                                }

                                # A scheduled task was deleted
                                if ( $System.EventID -eq 4699 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TaskName)

                                }

                                # A scheduled task was enabled
                                if ( $System.EventID -eq 4700 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TaskName)

                                }

                                # A scheduled task was disabled
                                if ( $System.EventID -eq 4701 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TaskName)

                                }

                                # A scheduled task was updated
                                if ( $System.EventID -eq 4702 ){
                                    # TODO later : +";"+$EventData.TaskContentNew needs to be proceeded : XML task definition
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ParentProcessId+";"+$EventData.ClientProcessId+";"+$EventData.TaskName)

                                }

                                # System audit policy was changed
                                if ( $System.EventID -eq 4719 ){
                                    # TODO later : SubcategoryGuid and AuditPolicyChanges values must be found and traducted
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.SubcategoryGuid+";"+$EventData.AuditPolicyChanges)

                                }

                                # A user account was created
                                if ( $System.EventID -eq 4720 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A user account was enabled
                                if ( $System.EventID -eq 4722 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # An attempt was made to reset an account's password
                                if ( $System.EventID -eq 4724 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A user account was disabled
                                if ( $System.EventID -eq 4725 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A user account was deleted
                                if ( $System.EventID -eq 4726 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A member was added to a security-enabled local group
                                if ( $System.EventID -eq 4732 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A member was removed from a security-enabled local group
                                if ( $System.EventID -eq 4733 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName)

                                }

                                # A security-enabled local group was changed
                                if ( $System.EventID -eq 4735 ){
                                    # If SamAccountName SidHistory and PrivilegeList = - other param that are not listed have changed
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.SamAccountName+";"+$EventData.SidHistory+";"+$EventData.PrivilegeList)

                                }

                                # A user account was changed
                                if ( $System.EventID -eq 4738 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.SamAccountName+";"+$EventData.UserPrincipalName+";"+$EventData.AllowedToDelegateTo+";"+$EventData.SidHistory+";"+$EventData.PrivilegeList+";"+$EventData.PasswordLastSet)

                                }

                                # A session was reconnected to a Window Station
                                if ( $System.EventID -eq 4778 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.AccountDomain+";"+$EventData.AccountName+";"+$EventData.ClientName+";"+$EventData.ClientAddress+";"+$EventData.SessionName)

                                }

                                # A session was disconnected from a Window Station
                                if ( $System.EventID -eq 4779 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.AccountDomain+";"+$EventData.AccountName+";"+$EventData.ClientName+";"+$EventData.ClientAddress+";"+$EventData.SessionName)

                                }

                                # The name of an account was changed
                                if ( $System.EventID -eq 4779 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.OldTargetUserName+";"+$EventData.NewTargetUserName)

                                }

                                # The name of an account was changed
                                if ( $System.EventID -eq 4781 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.OldTargetUserName+";"+$EventData.NewTargetUserName)

                                }

                                # A user's local group membership was enumerated
                                if ( $System.EventID -eq 4798 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.CallerProcessId+";"+$EventData.CallerProcessName)

                                }

                                # A security-enabled local group membership was enumerated
                                if ( $System.EventID -eq 4799 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.CallerProcessId+";"+$EventData.CallerProcessName)

                                }

                                # The workstation was locked
                                if ( $System.EventID -eq 4800 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.SessionId)

                                }

                                # The workstation was unlocked
                                if ( $System.EventID -eq 4801 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.SessionId)

                                }

                                # Key file operation
                                if ( $System.EventID -eq 5058 ){
                                    # Operation needs human traduction
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ClientProcessId+";"+$EventData.ClientCreationTime+";"+$EventData.Operation+";"+$EventData.KeyName+";"+$EventData.KeyFilePath)

                                }

                                # Key migration operation
                                if ( $System.EventID -eq 5059 ){
                                    # Operation needs human traduction
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ClientProcessId+";"+$EventData.ClientCreationTime+";"+$EventData.Operation+";"+$EventData.KeyName)

                                }

                                # Cryptographic operation
                                if ( $System.EventID -eq 5061 ){
                                    # Operation needs human traduction
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.Operation+";"+$EventData.KeyName)

                                }

                                # The Windows Filtering Platform has permitted a connection
                                if ( $System.EventID -eq 5156 ){
                                    # Direction: %%14592 inbound / %%14593 outbound
                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.Direction+";"+$EventData.SourceAddress+";"+$EventData.SourcePort+";"+$EventData.DestAddress+";"+$EventData.DestPort+";"+$EventData.Protocol+";"+$EventData.ProcessID+";"+$EventData.Application)

                                }

                                # The Windows Filtering Platform has permitted a bind to a local port
                                if ( $System.EventID -eq 5158 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SourceAddress+";"+$EventData.SourcePort+";"+$EventData.Protocol+";"+$EventData.ProcessId+";"+$EventData.Application)

                                }

                                # Credential Manager credentials were read
                                if ( $System.EventID -eq 5379 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.ProcessCreationTime+";"+$EventData.ClientProcessId+";"+$EventData.TargetName)

                                }

                            }

                            if ( ( $LogSearch -match "Sysmon" ) -or ( $LogPath -match "Sysmon" ) ){

                                # Process Create
                                if ( $System.EventID -eq 1 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Process Create;"+$EventData.ParentProcessId+";"+$EventData.ParentUser+";"+$EventData.ParentCommandLine+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.CommandLine)

                                }

                                # File creation time changed
                                if ( $System.EventID -eq 2 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";File creation time changed;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.CreationUtcTime+";"+$EventData.PreviousCreationUtcTime)

                                }

                                # Network connection detected
                                if ( $System.EventID -eq 3 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Network connection detected;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.Protocol+";"+$EventData.SourceIp+";"+$EventData.SourcePort+";"+$EventData.DestinationIp+";"+$EventData.DestinationPort)

                                }

                                # Sysmon service state changed
                                if ( $System.EventID -eq 4 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Sysmon service state changed;"+$EventData.State+";"+$EventData.SchemaVersion+";"+$EventData.Version)

                                }

                                # Process terminated
                                if ( $System.EventID -eq 5 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Process terminated;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image)

                                }

                                # Driver loaded into kernel
                                if ( $System.EventID -eq 6 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Driver loaded;"+$EventData.ImageLoaded+";"+$EventData.Signature+";"+$EventData.SignatureStatus+";"+$EventData.Signed+";"+$EventData.Hashes)

                                }

                                # Image loaded
                                if ( $System.EventID -eq 7 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Image loaded;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.ImageLoaded+";"+$EventData.Signature+";"+$EventData.SignatureStatus+";"+$EventData.Signed+";"+$EventData.Hashes)

                                }

                                # CreateRemoteThread detected
                                if ( $System.EventID -eq 8 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";CreateRemoteThread detected;"+$EventData.SourceProcessId+";"+$EventData.SourceUser+";"+$EventData.SourceImage+";"+$EventData.TargetProcessId+";"+$EventData.TargetUser+";"+$EventData.TargetImage+";"+$EventData.NewThreadId+";"+$EventData.StartAddress+";"+$EventData.StartModule+";"+$EventData.StartFunction)

                                }

                                # RawAccessRead detected
                                if ( $System.EventID -eq 9 ){

                                    #($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";RawAccessRead detected;"+$EventData.SourceProcessId+";"+$EventData.SourceImage+";"+$EventData.TargetProcessId+";"+$EventData.TargetImage+";"+$EventData.NewThreadId+";"+$EventData.StartAddress+";"+$EventData.StartModule+";"+$EventData.StartFunction)

                                }

                                # Process accessed
                                if ( $System.EventID -eq 10 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Process accessed;"+$EventData.SourceProcessId+";"+$EventData.SourceUser+";"+$EventData.SourceImage+";"+$EventData.TargetProcessId+";"+$EventData.TargetUser+";"+$EventData.TargetImage)

                                }

                                # File created
                                if ( $System.EventID -eq 11 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";File created;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.CreationUtcTime)

                                }

                                # RegistryEvent - Registry object added or deleted
                                if ( $System.EventID -eq 12 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";RegistryEvent;"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetObject)

                                }

                                # RegistryEvent - Registry value set
                                if ( $System.EventID -eq 13 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";RegistryEvent;"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetObject+";"+$EventData.Details)

                                }

                                # RegistryEvent - Registry object renamed
                                if ( $System.EventID -eq 14 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";RegistryEvent;"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.TargetObject+";"+$EventData.NewName)

                                }

                                # File stream created
                                if ( $System.EventID -eq 15 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";File stream created;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.Contents+";"+$EventData.CreationUtcTime)

                                }

                                # Sysmon config state changed
                                if ( $System.EventID -eq 16 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Sysmon config state changed;"+$EventData.Configuration+";"+$EventData.ConfigurationFileHash+";"+$EventData.UtcTime)

                                }

                                # PipeEvent - Pipe Created
                                if ( $System.EventID -eq 17 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";PipeEvent;"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.PipeName)

                                }

                                # PipeEvent - Pipe Connected
                                if ( $System.EventID -eq 18 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";PipeEvent;"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.PipeName)

                                }

                                # WmiEvent - WmiEventFilter activity detected
                                if ( $System.EventID -eq 19 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";WmiEvent;"+$EventData.EventType+";"+$EventData.User+";"+$EventData.Operation+";"+$EventData.Name+";"+$EventData.EventNameSpace+";"+$EventData.Query)

                                }

                                # WmiEvent - WmiEventConsumer activity detected
                                if ( $System.EventID -eq 20 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";WmiEvent;"+$EventData.EventType+";"+$EventData.User+";"+$EventData.Operation+";"+$EventData.Name+";"+$EventData."Type"+";"+$EventData.Destionation)

                                }

                                # WmiEvent - WmiEventConsumerToFilter activity detected
                                if ( $System.EventID -eq 21 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";WmiEvent;"+$EventData.EventType+";"+$EventData.User+";"+$EventData.Operation+";"+$EventData.Name+";"+$EventData.Consumer+";"+$EventData."Filter")

                                }

                                # Dns query
                                if ( $System.EventID -eq 22 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Dns query;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.QueryStatus+";"+$EventData.QueryName+";"+$EventData.QueryResults)

                                }

                                # File Delete
                                if ( $System.EventID -eq 23 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";File Delete;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.Hashes)

                                }

                                # Clipboard changed
                                if ( $System.EventID -eq 24 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Clipboard changed;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.Session+";"+$EventData.ClientInfo+";"+$EventData.Hashes)

                                }

                                # Process Tampering
                                if ( $System.EventID -eq 25 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";Process Tampering;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData."Type")

                                }

                                # File Deleted
                                if ( $System.EventID -eq 26 ){

                                    ($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";File Deleted;"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.Hashes)

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
