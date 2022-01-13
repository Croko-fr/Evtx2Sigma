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
PS> Evtx-Filter -ListLog

.EXAMPLE
Get the EventId list from Events in the current  `Application` log.
PS> Evtx-Filter -LogSearch Application -ListEventId

.EXAMPLE
Search `Security` log and shows all the events corresponding to selected EventId.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4627

.EXAMPLE
Search `Security` log and shows all the events corresponding to selected **EventId** that match a specific **Field** and a specific **FieldValue**.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4627 -Field 'LogonType' -FieldValue 2

.EXAMPLE
Search `Security` log and shows **only one** event corresponding to selected **EventId**.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne

.EXAMPLE
Search `Security` log for an event corresponding to selected **EventId** and shows **only one** event as **a SIGMA rule**.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma

.EXAMPLE
Search `Security` log for an event corresponding to selected **EventId** and outputs **only one** event as **a SIGMA rule** writen in the **OutDir** `./results/`.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma -OutDir ./results/

.EXAMPLE
Search `Security` log for all events corresponding to selected **EventId** and outputs **all events** as **SIGMA rules** writen in the **OutDir** `./results/`.
PS> Evtx-Filter -LogSearch 'Security' -EventId 4624 -ConvertToSigma -OutDir ./results/

.EXAMPLE
Search `Security` log for all events corresponding to the last **30 minutes TimeFrame**.
PS> Evtx-Filter -LogSearch 'Security' -TimeFrame 30m 

Possible values exemples : 15s / 30m / 12h / 7d / 3M

.EXAMPLE
Search `Security` log for all events corresponding to the specified **Period** between **-Begin** datetime and **-End** datetime.
Evtx-Filter -LogSearch Security -Period -Begin  "2021-12-20T10:00:00.000" -End  "2021-12-20T11:00:00.000"

.LINK
Online version: https://www.github.com/croko-fr/Evtx2Sigma

#>

function Evtx-Filter {

    Param (
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="ListLog" )]
        [Switch] $ListLog,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogSearch" )]
        [String] $LogSearch,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogPath" )]
        [String] $LogPath = "C:\Windows\System32\Winevt\Logs\Security.evtx",
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


    if ( $PSBoundParameters.ContainsKey('ListLog') ) {

        Write-Host "[+] Listing computer eventLogs"
        Get-WinEvent -ListLog * | Select-Object RecordCount,LogName
        break
            
    }


    if ( $PSBoundParameters.ContainsKey('LogPath') ) {

        if ( Test-Path "$LogPath" ) {

            Write-Host "[+] Searching EventLog : $LogPath"
            $XmlQuery = "<QueryList> <Query Id='0' Path='file://$LogPath'> <Select Path='file://$LogPath'> "
            $Request = "Get-WinEvent -Path '$LogPath'"

        } else {

            Write-Host "[x] No EventLog found with fullpath : $LogPath"
            break

        }

    }


    if ( $PSBoundParameters.ContainsKey('LogSearch') ) {

        $Logs = @(Get-WinEvent -ListLog *).LogName
        $LogName = @( $Logs -eq $LogSearch )

        if ( $LogName.Length -ne 0 ) {

            Write-Host "[+] Searching EventLog : $LogSearch"
            $XmlQuery = "<QueryList>`<Query Id='0' Path='$LogSearch'> <Select Path='$LogSearch'> "
            $Request = "Get-WinEvent -LogName $LogSearch"
    
        } else {

            Write-Host "[x] No EventLog found with name : $LogSearch"
            Break

        }

    }


    if ( $PSBoundParameters.ContainsKey('RawSearch') ) {

        Write-Host "[+] Searching with Raw keyword : '$RawSearch'"
        $match = Invoke-Expression $Request | Where-Object -Property Message -Match '$RawSearch' | Sort-Object -Descending
        if ( $match.count -ne 0 ) {
            Write-Host "[+] Match found :"
            $match
        } else {
            Write-Host "[x] Keyword not found."
            Break
        }

    }


    if ( $PSBoundParameters.ContainsKey('ListEventId') ) {

        Write-Host "[+] Searching EventID list."
        $ListOfEventId = Invoke-Expression $Request | Select-Object Id | Sort-Object Id -Unique

        if ( $ListOfEventId.count -ne 0 ) {

            $ListOfEventId.Id
            If ( $PSBoundParameters.ContainsKey('OutDir') ) {
                Write-Host "[+] Storing SIGMA rules in directory : $OutDir"
                ForEach ( $SearchId in $ListOfEventId.Id ) {
                    If ( $PSBoundParameters.ContainsKey('LogSearch') ) {
                        Evtx-Filter -LogSearch $LogSearch -EventId $SearchId -OnlyOne -ConvertToSigma -OutDir $OutDir
                    }
                    If ( $PSBoundParameters.ContainsKey('LogPath') ) {
                        Evtx-Filter -LogPath $LogPath -EventId $SearchId -OnlyOne -ConvertToSigma -OutDir $OutDir
                    }
                }            
            }

        } else {

            Write-Host "[x] EventLog seems to be empty."
            Break

        }
        
    }


    if ( $PSBoundParameters.ContainsKey('EventId') ) {

        Write-Host "[+] Searching EventId  : $EventId"
        if ( $Ids = $EventId.split(",") ) {
            $EventIdQuery = "*[System[EventID=" + $Ids[0]
            for ($i=1; $i -lt $Ids.Count; $i++) {
                $EventIdQuery += " or EventID=" + $Ids[$i]
            }
            $EventIdQuery += "]]"
        } else {
            $EventIdQuery = "*[System[EventID=$EventId]]"
        }

    }


    if ( $PSBoundParameters.ContainsKey('Field') -and $PSBoundParameters.ContainsKey('FieldValue') ) {

        Write-Host "[+] Searching Field    : $Field=$FieldValue"
        $FieldQuery = "*[EventData[Data[@Name='$Field']='$FieldValue']] or *[System[($Field='$FieldValue')]]"

    }



    if ( $PSBoundParameters.ContainsKey('TimeFrame') ) {
        Write-Host "[+] Limiting search on TimeFrame : $TimeFrame"
        if ( $TimeFrame.Contains("s") ) { $Number = $TimeFrame.Split("s"); $seconde = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddSeconds(-$seconde).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        if ( $TimeFrame.Contains("m") ) { $Number = $TimeFrame.Split("m"); $minute = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddMinutes(-$minute).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        if ( $TimeFrame.Contains("h") ) { $Number = $TimeFrame.Split("h"); $hour = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddHours(-$hour).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        if ( $TimeFrame.Contains("d") ) { $Number = $TimeFrame.Split("d"); $jour = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddDays(-$jour).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        if ( $TimeFrame.Contains("M") ) { $Number = $TimeFrame.Split("M"); $month = [convert]::ToInt32($Number[0]) ; $Begin = (Get-Date).AddHours(-1).AddMonths(-$month).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        Write-Host "[+] Search begin : "$Begin
        $End = (Get-Date).AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Write-Host "[+] Search end   : "$End
        $TimeFrameQuery = "*[System[TimeCreated[@SystemTime&gt;='$Begin' and @SystemTime&lt;='$End']]]"
    }


    if ( $PSBoundParameters.ContainsKey('Period') ) {
        Write-Host "[+] Limiting search on Period :"
        Try { Get-Date -Date "$Begin" | Out-Null } Catch { Write-Host -ForegroundColor Red "[x] Period : BEGIN date is not valid."; break }
        Try { Get-Date -Date "$End" | Out-Null } Catch { Write-Host -ForegroundColor Red "[x] Period : END date is not valid."; break }
        $Begin = (Get-Date -date "$Begin" ).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Write-Host "[+] Search begin : "$Begin
        $End = (Get-Date -date "$End" ).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Write-Host "[+] Search end   : "$End
        $TimeFrameQuery = "*[System[TimeCreated[@SystemTime&gt;='$Begin' and @SystemTime&lt;='$End']]]"
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

        Write-Host "[+] XPath query :"$XmlQuery

        if ( $PSBoundParameters.ContainsKey('OnlyOne') ) {
            $Request = 'Get-WinEvent -FilterXml "' + $XmlQuery + '" -MaxEvent 1 -ErrorAction SilentlyContinue | Sort-Object -Descending'
        } else {
            $Request = 'Get-WinEvent -FilterXml "' + $XmlQuery + '" -ErrorAction SilentlyContinue | Sort-Object -Descending'
        }
        
        Write-Host "[+] Launching XPath REQUEST : "$Request

        $Events = Invoke-Expression $Request

        if ( $Events.Count -eq 0 ) {

            Write-Host "[x] No matching event found."

        } else {

            Write-Host "[+]"$Events.Count" matching event found."

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
                                        $System.add( "EventID" , $eventXML.Event.System.EventID )
                                        if ( $eventXML.Event.System.EventID.'#attributes'.Qualifiers ) {
                                            $System.add( "Qualifiers" , $eventXML.Event.System.EventID.'#attributes'.Qualifiers )
                                        }
                                        break
                                        }
                        default       {
                                        If ( ( $eventXML.Event.System.ChildNodes[$i].'#text' -ne $null ) -Or ( $eventXML.Event.System.ChildNodes[$i].'#text' -ne "NULL" ) ) {
                                            $System.add( $eventXML.Event.System.ChildNodes[$i].Name , $eventXML.Event.System.ChildNodes[$i].'#text' )
                                        }
                                        break
                                        }
                    }
                }

                for ($i=0; $i -lt $eventXML.Event.UserData.FirstChild.ChildNodes.Count; $i++) {
                    $LogType = "UserData"
                    if ( ( $eventXML.Event.UserData.ChildNodes[$i].'#text' -ne $null ) -Or ( $eventXML.Event.UserData.ChildNodes[$i].'#text' -ne "NULL" ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "null" ) ) {
                        $UserData.add( $eventXML.Event.UserData.FirstChild.ChildNodes[$i].Name , $eventXML.Event.UserData.FirstChild.ChildNodes[$i].'#text' )
                    }
                }
                for ($i=0; $i -lt $eventXML.Event.EventData.ChildNodes.Count; $i++) {
                    $LogType = "EventData"
                    if ( ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne $null ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "NULL" ) -Or ( $eventXML.Event.EventData.ChildNodes[$i].'#text' -ne "null" ) ) {
                        $EventData.add( $eventXML.Event.EventData.ChildNodes[$i].Name , $eventXML.Event.EventData.ChildNodes[$i].'#text' )
                    }
                }

                if ( $PSBoundParameters.ContainsKey('ConvertToSigma') -eq $true ) {

                    $Result = [String]"title: " + $System.Provider_Name + " EventID " + $System.EventID + "`r`n"
                    $Result += "id: " + (New-Guid).Guid + "`r`n"
                    # Find description for known EventID
                    $CatalogFilePath = (Get-Location).Path+"\"+$CatalogFile
                    if ( Test-Path $CatalogFilePath ) {
                        $Match = (( gc $CatalogFilePath ) -match ($System.Provider_Name+";"+$System.EventID+";") ) -split ";"
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
    
                            if ( ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne $null ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "NULL" ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "null" ) -and ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "Null" ) ) {
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

							if ( ( $LogSearch -eq "Security" ) -or ( $LogPath -match "Security" ) ){

								if ( $System.EventID -eq 4624 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.AuthenticationPackageName+";"+$EventData.IpAddress+";"+$EventData.IpPort+";"+$EventData.LogonProcessName+";"+$EventData.LogonType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.ProcessName)

								}

								if ( $System.EventID -eq 4625 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.AuthenticationPackageName+";"+$EventData.IpAddress+";"+$EventData.IpPort+";"+$EventData.LogonProcessName+";"+$EventData.LogonType+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.ProcessName)

								}

								if ( $System.EventID -eq 4688 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+";"+$EventData.ParentProcessName+";"+$EventData.NewProcessName)

								}

								if ( $System.EventID -eq 4689 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.SubjectDomainName+"\"+$EventData.SubjectUserName+";"+$EventData.ProcessName)

								}

								if ( $System.EventID -eq 4732 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.MemberSid)

								}

								if ( $System.EventID -eq 4733 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.SubjectDomainName+";"+$EventData.SubjectUserName+";"+$EventData.TargetDomainName+";"+$EventData.TargetUserName+";"+$EventData.MemberSid)

								}

							}

							if ( ( $LogSearch -eq "Sysmon" ) -or ( $LogPath -match "Sysmon" ) ){

								# Process Create
								if ( $System.EventID -eq 1 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.User+";"+$EventData.ProcessId+";"+$EventData.CommandLine+";"+$EventData.ParentProcessId+";"+$EventData.ParentCommandLine+";"+$EventData.Image+";")

								}

								# File creation time changed
								if ( $System.EventID -eq 2 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.CreationUtcTime+";"+$EventData.PreviousCreationUtcTime)

								}

								# Network connection detected
								if ( $System.EventID -eq 3 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.ProcessId+";"+$EventData.User+";"+$EventData.Image+";"+$EventData.Protocol+";"+$EventData.SourceIp+";"+$EventData.SourcePort+";"+$EventData.DestinationIp+";"+$EventData.DestinationPort)

								}

								# Sysmon service state changed
								if ( $System.EventID -eq 4 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.State+";"+$EventData.SchemaVersion+";"+$EventData.Version)

								}

								# Process terminated
								if ( $System.EventID -eq 5 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.ProcessGuid+";"+$EventData.RuleName)

								}

								# Driver loaded
								if ( $System.EventID -eq 6 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.ImageLoaded+";"+$EventData.Signature+";"+$EventData.SignatureStatus+";"+$EventData.Signed+";"+$EventData.Hashes)

								}

								# CreateRemoteThread detected
								if ( $System.EventID -eq 8 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.SourceProcessId+";"+$EventData.SourceImage+";"+$EventData.TargetProcessId+";"+$EventData.TargetImage+";"+$EventData.NewThreadId+";"+$EventData.StartAddress+";"+$EventData.StartModule+";"+$EventData.StartFunction)

								}

								# File created
								if ( $System.EventID -eq 11 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.TargetFileName+";"+$EventData.CreationUtcTime)

								}

								# Registry object added or deleted
								if ( $System.EventID -eq 12 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.TargetObject+";"+$EventData.RuleName)

								}

								# Registry value set
								if ( $System.EventID -eq 13 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.EventType+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.TargetObject+";"+$EventData.Details)

								}

								# Sysmon config state changed
								if ( $System.EventID -eq 16 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$EventData.Configuration+";"+$EventData.ConfigurationFileHash+";"+$EventData.UtcTime)

								}

								# Dns query
								if ( $System.EventID -eq 22 ){

									($System.SystemTime+";"+$System.Computer+";"+$System.EventID+";"+$Event.TaskDisplayName+";"+$System.ProcessID+";"+$System.ThreadID+";"+$EventData.ProcessId+";"+$EventData.Image+";"+$EventData.QueryName+";"+$EventData.QueryResults+";"+$EventData.QueryStatus)

								}

							}

						} else {

							Write-Host "System :"
							$System | ConvertTo-Json
							Write-Host "EventData :"
							$EventData | ConvertTo-Json

						}

                    }
        
                }


            } # End ForEach

        } # End If Event.Count -gt 0

    }    

}
