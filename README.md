# Evtx-Filter

Repository to query live or offline Windows eventlogs and output sigma rules.
As we already parse EventLog file you can show a timeline instead.

## .SYNOPSIS

Search script for easy Evtx lookup and SIGMA rule generation.

## .DESCRIPTION
With this script you will be able to get informations from evtx files.
You can query a Log for a single or more EventId(s).
You can list all EventIds from a specific Log.
You can search for an EventId and a specific value for another field.
You can generate a SIGMA rule from your search.

### .PARAMETER ListLog
Switch to list all logs available on the system.
Result : gives RecordCount per LogName

### .PARAMETER LogSearch
Gives the scope of the search. Must be a valid Logname.
Defaults to the Security log.

### .INPUTS
None. You cannot pipe objects to Add-Extension.

### .OUTPUTS
Screen output or file output as json or sigma rule.

### .EXAMPLE

List all Logs with corresponding number of events.

```powershell
Evtx-Filter -ListLog
```

### .EXAMPLE

Get the EventId list from Events in the current  `Application` log.

```powershell
Evtx-Filter -LogSearch Application -ListEventId
```

### .EXAMPLE

Search `Security` log and shows all the events corresponding to selected EventId.

```powershell
 Evtx-Filter -LogSearch 'Security' -EventId 4627
```

### .EXAMPLE

Search `Security` log and shows all the events corresponding to selected **EventId** that match a specific **Field** and a specific **FieldValue**.

```powershell
Evtx-Filter -LogSearch 'Security' -EventId 4627 -Field 'LogonType' -FieldValue 2
```

### .EXAMPLE

Search `Security` log and shows **only one** event corresponding to selected **EventId**.

```powershell
Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne
```

### .EXAMPLE

Search `Security` log for an event corresponding to selected **EventId** and shows **only one** event as **a SIGMA rule**.

```powershell
Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma
```

### .EXAMPLE

Search `Security` log for an event corresponding to selected **EventId** and outputs **only one** event as **a SIGMA rule** writen in the **OutDir** `./results/`.

```powershell
Evtx-Filter -LogSearch 'Security' -EventId 4624 -OnlyOne -ConvertToSigma -OutDir ./results/
```

### .EXAMPLE

Search `Security` log for all events corresponding to selected **EventId** and outputs **all events** as **SIGMA rules** writen in the **OutDir** `./results/`.

```powershell
Evtx-Filter -LogSearch 'Security' -EventId 4624 -ConvertToSigma -OutDir ./results/
```

### .EXAMPLE

Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the last **30 minutes TimeFrame**.

```powershell
Evtx-Filter -LogSearch "Microsoft-Windows-Sysmon/Operational" -TimeFrame 30m 
```

Possible values exemples : 15s / 30m / 12h / 7d / 3M

### EXAMPLE

Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the specified **Period** between **-Begin** datetime and **-End** datetime.

```powershell
Evtx-Filter -LogSearch "Microsoft-Windows-Sysmon/Operational" -Period -Begin  "2021-12-20T10:00:00.000" -End  "2021-12-20T11:00:00.000"
```

### .EXAMPLE

Search `Microsoft-Windows-Sysmon/Operational` log for all events corresponding to the last **1 hour** and outputs on screen as a timeline.

```powershell
Evtx-Filter -LogSearch "Microsoft-Windows-Sysmon/Operational" -TimeFrame 1h -ConvertToTimeLine
```

### .LINK

Online version: https://www.github.com/croko-fr/Evtx2Sigma

### .TODO

- [x] Fix Search with Evtx files input
- [x] Rewrite all search with XPath ( faster )
- [x] Write all exemples
- [ ] Add more EventID for Security logs
- [ ] Add more logs for Timeline
- [ ] Find a way to handle options better
- [ ] Find a way to speed the request
- [ ] Split project in mutliple one ?

### .THANKS

- Florian Roth and Thomas Patzke : for this awesome project --> [SIGMA](https://github.com/SigmaHQ/sigma)


