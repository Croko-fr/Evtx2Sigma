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
PS> Evtx-Filter -ListLog
List all Logs and counts the number of events in them.

.EXAMPLE
PS> Evtx-Filter -LogSearch Application -ListEventId
List Application log and shows the available EventId list.

.EXAMPLE
PS> Evtx-Filter -LogSearch 'Security' -EventId 4627
List Security log and shows the events for the selected EventId only.

.EXAMPLE
PS> Evtx-Filter -LogSearch Security -EventId 4627 -Field LogonType -FieldValue 2
List Security log and shows the events for the selected EventId and matches a specific Field and a specific value.

.LINK
Online version: https://www.github.com/croko-fr/sigma

#>

function Evtx-Filter {

    Param (
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="ListLog" )]
        [Switch] $ListLog,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="ListEventId" )]
        [Parameter( ParameterSetName="RawSearch" )]
        [String] $LogSearch,
        [Parameter( Mandatory=$true , Position=0, ParameterSetName="LogPath" )]
        [Parameter( ParameterSetName="ListEventId" )]
        [Parameter( ParameterSetName="RawSearch" )]
        [String] $LogPath = "C:\Windows\System32\Winevt\Logs\Security.evtx",
        [Parameter( ParameterSetName="RawSearch" )]
        [String] $RawSearch,
        [Parameter( ParameterSetName="ListEventId" )]
        [Switch] $ListEventId,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [Int] $EventId,
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
        [String] $Description,
        [Parameter( ParameterSetName="LogSearch" )]
        [Parameter( ParameterSetName="LogPath" )]
        [String] $OutDir
    )


    if ( $PSBoundParameters.ContainsKey('OnlyOne') ) {
        $Request = "Get-WinEvent -MaxEvent 1"
    } else {
        $Request = "Get-WinEvent"
    }


    if ( $PSBoundParameters.ContainsKey('ListLog') ) {

        Write-Host "[+] Listing computer eventLogs"
        Get-WinEvent -ListLog * | Select-Object RecordCount,LogName
    
    }


    if ( $PSBoundParameters.ContainsKey('LogPath') ) {

        if ( Test-Path "$LogPath" ) {

            Write-Host "[+] Searching EventLog : $LogPath"
            $RequestLog = $Request+" -Path $LogPath"

        } else {

            Write-Host "[x] [x] No EventLog found with fullpath : $LogPath"
            break

        }

    }
    	

    if ( $PSBoundParameters.ContainsKey('LogSearch') ) {

        $Logs = @(Get-WinEvent -ListLog *).LogName
        $LogName = @( $Logs -eq $LogSearch )

        if ( $LogName.Length -ne 0 ) {

            Write-Host "[+] Searching EventLog : $LogSearch"
            $RequestLog = $Request+" -LogName $LogSearch"

        } else {

            Write-Host "[x] No EventLog found with name : $LogSearch"
            Break

        }

    }


    if ( $PSBoundParameters.ContainsKey('RawSearch') ) {

        Write-Host "[+] Searching with Raw keyword : '$RawSearch'"
        $match = Invoke-Expression $Request | Where-Object -Property Message -Match '$RawSearch'
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
        $ListOfEventId = Invoke-Expression $RequestLog | Select-Object Id | Sort-Object Id -Unique

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

        if ( $PSBoundParameters.ContainsKey('Field') -and $PSBoundParameters.ContainsKey('FieldValue') ) {

#            $MyEventId = "4689"
#            $MyField = "Status"
#            $MyValue = "0x0"
            Write-Host "[+] Searching Field    : $Field=$FieldValue"

            if ( $PSBoundParameters.ContainsKey('LogSearch') ) {
                $query = "<QueryList>`r`n  <Query Id='0' Path='$LogSearch'>`r`n    <Select Path='$LogSearch'>`r`n    *[System[(EventID=$EventId)] and EventData[Data[@Name='$Field']='$FieldValue']] or *[System[(EventID=$EventId)] and System[($Field='$FieldValue')]]`r`n    </Select>`r`n  </Query>`r`n</QueryList>`r`n"
            }

            if ( $PSBoundParameters.ContainsKey('LogPath') ) {
                $query = "<QueryList>`r`n  <Query Id='0' Path='$LogPath'>`r`n    <Select Path='$LogPath'>`r`n    *[System[(EventID=$EventId)] and EventData[Data[@Name='$Field']='$FieldValue']] or *[System[(EventID=$EventId)] and System[($Field='$FieldValue')]]`r`n    </Select>`r`n  </Query>`r`n</QueryList>`r`n"
            }

        } else {
                
            if ( $PSBoundParameters.ContainsKey('LogSearch') ) {
                $query = "<QueryList>`r`n  <Query Id='0' Path='$LogSearch'>`r`n    <Select Path='$LogSearch'>`r`n    *[System[(EventID=$EventId)] ]`r`n    </Select>`r`n  </Query>`r`n</QueryList>`r`n"
            }

            if ( $PSBoundParameters.ContainsKey('LogPath') ) {
                $query = "<QueryList>`r`n  <Query Id='0' Path='$LogPath'>`r`n    <Select Path='$LogPath'>`r`n    *[System[(EventID=$EventId)] ]`r`n    </Select>`r`n  </Query>`r`n</QueryList>`r`n"
            }
              
        }

        $query
        $Request = $Request+' -FilterXml "$query" -ErrorAction SilentlyContinue'

    }

    
    If ( -not $PSBoundParameters.ContainsKey('ListEventId') -and -not $PSBoundParameters.ContainsKey('ListLog') ) {

        Write-Host "REQUEST : "$Request -ForegroundColor Red

        $Events = Invoke-Expression $Request

        if ( $Events.Count -eq 0 ) {

            Write-Host "[x] No matching event found."

        } else {

            # TODO : Enqueter sur Options / NetworkAddress 
            ForEach ( $Event in $Events ) {

                $eventXML = [xml]$Event.ToXml()
                $System = @{}
                $UserData = @{}
                $EventData = @{}

                $System.add( "Provider" , $eventXML.Event.System.ChildNodes[0].Name )
                $System.add( "Guid" , $eventXML.Event.System.ChildNodes[0].Guid )
                if ( $eventXML.Event.System.ChildNodes[0].EventSourceName ) {
                    $System.add( "EventSourceName" , $eventXML.Event.System.ChildNodes[0].EventSourceName )
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

                if ( $PSBoundParameters.ContainsKey('ConvertToSigma') ) {

                    $Result = [String]"title: " + $System.Provider + " EventID " + $System.EventID + "`r`n"
                    $Result += "id: " + (New-Guid).Guid + "`r`n"
                    if ( $PSBoundParameters.ContainsKey('Description') ) {
                        $Result += "description: " + $Description + "`r`n"
                    } else {
                        $Result += "description: " + $System.Provider + "`r`n"
                    }
                    $Result += "references:" + "`r`n"
                    $Result += "    - https://www.awesome-security-blog.com/vulns/cve-2021-xxxxx" + "`r`n"
                    $Result += "tags:" + "`r`n"
                    $Result += "    - cve-2021-xxxxx" + "`r`n"
                    $Result += "    - mitre.attack.txxxx.xxx" + "`r`n"
                    $Result += "status: stable / testing / experimental" + "`r`n"
                    $Result += "author: Croko" + "`r`n"
                    $Result += "date:" + (Get-Date).GetDateTimeFormats()[0] + "`r`n"
                    $Result += "modified:" + (Get-Date).GetDateTimeFormats()[0] + "`r`n"
                    $Result += "logsource:" + "`r`n"
                    $Result += "    product: windows" + "`r`n"
                    If ( $System.Channel ) {
                        $Result += "    service: " + $System.Channel.ToLower() + "`r`n"
                    } else {
                        $Result += "    service: " + $System.Provider + "`r`n"
                    }
                    $Result += "detection:" + "`r`n"
                    $Result += "    selection:" + "`r`n"
                    foreach ( $Data in $System.Keys ) {
                            $Result += "        $Data|contains: " + $System.$Data + "`r`n"
                    }

                    $Result += "    filter:" + "`r`n"

                    foreach ( $Data in $(Get-Variable "$LogType" -ValueOnly).Keys ) {

                        if ( ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne $null ) -or ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "NULL" ) -or ( $(Get-Variable "$LogType" -ValueOnly).$Data -ne "null" ) ) {
                            # Add your selection of Keys here
                            if ( (($(Get-Variable "$LogType" -ValueOnly).$Data).Split("`r`n")).Count -eq 1 ) {

                                $Result += "        $Data|contains: " + $(Get-Variable "$LogType" -ValueOnly).$Data + "`r`n"

                            } else {

                                $MultiLine = ($(Get-Variable "$LogType" -ValueOnly).$Data).Split("`r`n")
                                foreach ( $line in $MultiLine ) {
                                    if ( $line -ne "" ) {
                                        $Result += "        $Data|contains: " + $line.trim() + "`r`n"
                                    }
                                }

                            }
                        }

                    }

                    $Result += "    timeframe: 15s / 30m / 12h / 7d / 3M" + "`r`n"
                    $Result += "    condition: selection and filter" + "`r`n"
                    $Result += "fields:" + "`r`n"
                    foreach ( $SysData in $System.Keys ) {
                        $Result += "    - " + $SysData + "`r`n"
                    }
                    foreach ( $Data in $(Get-Variable "$LogType" -ValueOnly).Keys ) {
                        $Result += "    - " + $Data + "`r`n"
                    }
                    $Result += "falsepositives:" + "`r`n"
                    $Result += "    - Explain what could be falsepositives / None" + "`r`n"
                    $Result += "level: informational / low / medium / high / critical" + "`r`n"
                }


                if ( $PSBoundParameters.ContainsKey('OutDir') ) {
        
                    if ( !(Test-Path $OutDir) ) {

                        Write-Host "[+] Creating output directory : $OutDir"
                        New-Item -Path $OutDir -type directory -Force 

                    }

                    If ( $PSBoundParameters.ContainsKey('OnlyOne') ) { 

                        $FileName = $OutDir+"\Windows_EventLog_"+$System.EventId

                    } Else {
                    
                        $FileName = $OutDir+"\Windows_EventLog_"+$System.EventId+"_"+$System.EventRecordID
                                            
                    }

                    If ( $PSBoundParameters.ContainsKey('ConvertToSigma') ) {

                        Write-Host "[+] Writing SIGMA rule : $Filename.yml"
                        Set-Content -Path $Filename".yml" -Value ( $Result )

                    } Else {
                    
                        Write-Host "[+] Writing SIGMA rule : $Filename.json"
                        Set-Content -Path $Filename".json" -Value ($System + $EventData | ConvertTo-Json)

                    }

                } else {
        
                    if ( $PSBoundParameters.ContainsKey('ConvertToSigma') ) {

                        $Result

                    } else {

                        $System + $EventData | ConvertTo-Json
                        
                    }
        
                }


            } # End ForEach

        } # End If Event.Count -gt 0

    }    

}
