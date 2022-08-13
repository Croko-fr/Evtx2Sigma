# EvtxFilter project


Disclaimer :
- Sorry for my english
- Sorry for my powershell


## Why this project ?

I came to this project because I was bored to use tools that parse eventlog.
I was never able to really figure out how the parsing part was done and I need to understand to work well.
I also wanted to use a manner that will not change names, if it is possible.
I figured out that the usage I wanted, was to parse live and offline EventLogs.

I was not able to really understand how the eventlogs where structured and why it was difficult to parse at the beginning.
I think I understand really better now ;)


## But wwwwhhhyyyyyy Powershell ?

Just because it was a challenge project for me to learn powershell too.
And powershell is on all Windows computer where the eventlogs are too, for live query it's easier.


## Meeting with the Sigma project

After the parsing part, I wanted to request easily the eventlogs to make research on each event to better understand what can be interesting in native EventLogs.
I also tryed to get a good insight of what SIGMA rules are searching for, and I found a lot of ressources thanks to **Florian Roth** and **Thomas Patzke** awesome project --> [SIGMA](https://github.com/SigmaHQ/sigma)

But was also a little frustrated to find a little number of rules with native EventLogs, compared to **Sysmon** ones. ( Hope to create some content soon :) )


## The search is the key

Each action you make on a computer may or may not generate an event in EventLogs.
That's why I thought that requesting eventlogs easily could really be usefull to see what events were generated for an action.

The function implemented permit to request for **one EventLog** :
- by **EventID**
- by a specified field and a value
- for a **timeFrame**
- for a **period** between 2 datetime

After those features, I was interested in SIGMA rules creation and thought it could help me to create rules.
I added possibility to output Sigma rule from a search : **ConvertToSigma** option.

To export a successful login event as Sigma rule :

```powershell
# Import to script
Import-Module .\EvtxFilter.ps1

# Request a Sigma output to SCREEN
EvtxFilter -LogSearch "Security" -EventId "4624" -OnlyOne -ConvertToSigma

# Request a Sigma output to a destination DIRECTORY
EvtxFilter -LogSearch "Security" -EventId "4624" -OnlyOne -ConvertToSigma -outdir "myrules"
```

It will give you all fields and you need to triage the interesting part to get a usefull Sigma rule.
The Sigma structure may be compliant with SIGMA specification page : https://github.com/SigmaHQ/sigma/wiki/Specification


## Begin to dig and you dig deeper and deeper

With this Sigma rule creation, I thought that it could be really nice to get the events I now know in a human-readable manner.
I started with **Sysmon** events, as there where only a limited number of events, and introduced an option to convert events to a timeline : **ConvertToTimeLine**.

If you use Sysmon, try this, trust me you will enjoy it :)

```powershell
# Import to script
Import-Module .\EvtxFilter.ps1

# Request live Sysmon EventLog
EvtxFilter -LogSearch "Microsoft-Windows-Sysmon/Operational" -ConvertToTimeLine | Out-GridView
```

But **Sysmon** may not always be used and that doesn't resolve my main reflexion about what could be usefull in native EventLogs.
So I began with trying to find what events where generated in what EventLog.

Here, you can try to get list of EventID in Defender log so we can query each of them to get the content.

```powershell
# Import to script
Import-Module .\EvtxFilter.ps1

# Request "Microsoft-Windows-Windows Defender/Operational" EventLog for EventID list
EvtxFilter -LogSearch "Microsoft-Windows-Windows Defender/Operational" -ListEventId
```

As the work was already done, you can get a timeline for defender

```Powershell
# Import to script
Import-Module .\EvtxFilter.ps1

# Request "Microsoft-Windows-Windows Defender/Operational" EventLog for history,detection and actions
EvtxFilter -LogSearch "Microsoft-Windows-Windows Defender/Operational" -ConvertToTimeLine | Out-GridView
```

## What's next ?

I tried to get all EventLogs I had on my computer with all my activity, and the corresponding events for each log.
I selected only those which give me some usefull informations, some may be missing.

I like the idea to get a nice timeline with native EventLog but I need to find key eventIds and be able to request on all logs available.

If you have other ideas that could be usefull feel free to reach me on twitter **@croko-fr**.
You can ask here for enhancements or pull requests to contribute.

Dunno if it could be nice to have Sigma rules that will alert on events that are part of the system like scheduled task creation and user creation and many others.
Need to focus on the SigmaHQ converage on all events I found in native eventLogs to contribute.


## Hopes

I really hope it will help people to understand what events in what eventlog can be revelant.
I hope that people can see easily the content of the logs or event and get timeline really fast for forensic research.
