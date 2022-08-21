#Declare Variables

$c = 0
$iparray = @()
$rdpkillleruserlog = @()
$iparray = @()
$usernamearray =@()

$filter = @{
	Logname = 'Security'
	Keywords='9007199254740992' #audit success = '9007199254740992' FAILURE = '4503599627370496'
}

#Get all the logs from the security events database matching the hash table
$RDPLogs = @()
$RDPLogs = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

foreach($log in $RDPLogs){

if($log.Id -eq "4624"){

#$log.MachineName
#$log.TimeCreated
#$log.Message

#grab the account name
#split the log entry into an array based on newline
$splitter = $log.MachineName -Split "`r`n"
$splitter = $log.Message.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

#$splitter[26]

#regex to grab IP addresses out of the message in each log
$regex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’

$Matched = $splitter[26] |select-string  -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }

#$Matched


$iparray += $Matched

$usernamearray0 = $splitter[14] -split '\s+'
$usernamearray0  = $usernamearray0.replace(' ','')


#Grab the username from the message entry in the log
$username = $usernamearray0[3]
$usernamearray += $username 


if($Matched){
$time = $log.TimeCreated
Write-Host "User: $username Authenticated from: $Matched at $time" -ForegroundColor Red
}
}

}

$iparray |Select-Object -Unique |Sort-Object
$usernamearray |Select-Object -Unique |Sort-Object
