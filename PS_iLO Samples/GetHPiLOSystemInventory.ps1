## -------------------------------------------------------------------------------------------------------------
##      Description: Inventory of server
##
## DISCLAIMER
## The sample scripts are not supported under any HP standard support program or service.
## The sample scripts are provided AS IS without warranty of any kind. 
## HP further disclaims all implied warranties including, without limitation, any implied 
## warranties of merchantability or of fitness for a particular purpose. 
##
## Description of Fields in Output CSV
## ERROR – ERROR message is returned from the server side.
## EXCEPTION - Exception is thrown by the cmdlet which can be due to invalid user input.
## LOGIN FAILED – Invalid login credentials were given.
## N/A - Information is not available.
##    
## Scenario
##     	Use HPiLOCmdlets to collect information about servers. The script validates the IPs at three levels:
##        1. Finds reachable IPs in the input
##        2. Checks the input credentials
##        3. Validates the certificate 
##
## Reference
##     https://www.hpe.com/us/en/product-catalog/detail/pip.5440657.html
##		
##
## Input parameters:
##
##       InputiLOCSV -> Path to the Input CSV file containing iLO IP, Username and Password   
##       OutputCSV    -> Path of Output csv file. Path should contain filename with .csv extension
##       iLOIP        -> Parameter to give iLO IP via command line
##       iLOUsername  -> Parameter to give iLO Username via command line
##       iLOPassword  -> Parameter to give iLO Password via command line
##
##       Option 1: Specify InputiLOCSV
##                 Specify list of iLO IP addresses along with Username and Password in a CSV file.
##                 Format is :  IP,Username,Password
##                 Parameter OutputCSV is optional. If it is not specified, output file is created in the current directory.
##                 
##
##       Option 2: Specify iLOIP, iLOUsername and iLOPassword
##       Parameter OutputCSV is optional. If it is not specified, output file is created in the current directory. 
##
## Prerequisites
##     	 Microsoft .NET Framework 4.5
##       HPiLOCmdlets latest (1.4.0.x) - http://h20566.www2.hpe.com/hpsc/swd/public/readIndex?sp4ts.oid=1008862655&lang=en&cc=us
##	     Powershell Version 4.0 and above
##       Prepare a CSV file with following fields (Optional) - IP, Username, Password
##
## Platform tested
##        Gen8 and Gen9 servers
##
## Version: 1.0.0.0
## -------------------------------------------------------------------------------------------------------------


    <#
  .SYNOPSIS
    Performs an inventory of server Hardware components.  
  
  .DESCRIPTION
    Performs an inventory of server hardware components using HPiLOCmdlets. There are two ways to supply the input. Either the parameters InputiLOCSV and OutputCSV should be given or, iLOIP, iLOUsername and iLOPassword should be specified.
    This works on G8 and Gen 9 servers. 
        
  .EXAMPLE
    PS C:\> .\GetHPiLOSystemInventory.ps1 -InputiLOCSV C:\Users\admin\Desktop\JIO\iloserver.csv -OutputCSV C:\output.csv
            Output file path -> C:\output.csv

    In this example, path of the input CSV file is speecified for "InputiLOCSV" and path of output CSV file is given for "OutputCSV"

  .EXAMPLE        
    PS C:\> .\GetHPiLOSystemInventory.ps1 -iLOIP 192.168.10.12 -iLOUsername admin -iLOPassword admin123 
            Output file path -> C:\SystemInventory_13Jul2017.csv

    In this example, iLO Ip address, it's username and password are specified.

  .EXAMPLE        
    PS C:\> .\GetHPiLOSystemInventory.ps1 -iLOIP 192.168.10.12 -iLOUsername admin -iLOPassword admin123 
            Output file path -> C:\SystemInventory_13Jul2017.csv

    In this example, a range is specified for IP along with username and password.

  .PARAMETER InputiLOCSV
    Name of the CSV file containing iLO IP Address, ILO Username and iLO Password.
    The format is: IP,Username,Password

  .PARAMETER OutputCSV
    Path of Output CSV file. Path should contain filename with .csv extension.
    If this parameter is not specified, then output file will be created in the current working directory.

  .PARAMETER iLOIP
    IP address of the ILO. A range of iLO IPs and multiple IPS can also be provided. 
    Example1 - 30.40.50.60
    Example2 - 30.40.50.1-50
    Example3 - 30.40.50.1,30.40.50.2,30.40.50.3

  .PARAMETER iLOUsername
    Specifies the single username for all the iLOs or a list of usernames for each iLO in the input iLO list.

  .PARAMETER iLOPassword
    Specifies the single password for all the iLOs or a list of passwords for each iLO in the input iLO list.

  .PARAMETER DisableCertificateAuthentication
    If this switch parameter is present then server certificate authentication is disabled for the execution of this cmdlet. If not present it will execute according to the 
    global certificate authentication setting. The default is to authenticate server certificates.

  .Notes
   
  .Link
    http://www.hpe.com/servers/powershell

 #>

    [CmdletBinding(DefaultParametersetName="CSVInput")] 
    Param (

    [Parameter(ParameterSetName="CSVInput")]
        [string]$InputiLOCSV ="",

    [Parameter(ParameterSetName="CSVInput")]
    [Parameter(ParameterSetName="CommandLine")]
        [string]$OutputCSV ="",

    [Parameter(ParameterSetName="CommandLine")]
        [Array]$iLOIP        = "",

    [Parameter(ParameterSetName="CommandLine",Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
        [Array]$iLOUsername = "",

    [Parameter(ParameterSetName="CommandLine",Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
        [Array]$iLOPassword  = "",

    [Parameter(Mandatory=$false)]
    [switch] $DisableCertificateAuthentication

    )
 
    $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    $ModulePath = Join-Path $PSScriptRoot "HPiLOCmdlets\HPiLOCmdlets.psm1"
    import-module $ModulePath

    ## -------------------------------------------------------------------------------------------------------------
    ##                     FUNTION TO RETRIEVE IPs WHICH HAVE A VALID CERTIFICATE   
    ## -------------------------------------------------------------------------------------------------------------
    function Get-ValidIPs{
        
        Param (
            [Array]$IPs,
            [Array]$Usernames,
            [Array]$Passwords
        )
        
        $ReturnArray = @{}
        if($Script:InvalidInputWithQuotes -eq $null)
        {
            [Array]$Script:InvalidInputWithQuotes = $null
        }
        if($Script:InvalidCertificateInput -eq $null)
        {
            [Array]$Script:InvalidCertificateInput = $null
        }
        for($i=0; $i -lt $IPs.Count; $i++)
        {
            $Error.Clear()
            if(($IPs.Count -ne 1) -and (($Usernames.Count -ne 1) -and ($Passwords.Count -ne 1)))
            {
                [String]$AssetIP = $IPs[$i]
                [String]$AssetUsername = $Usernames[$i]
                [String]$AssetPassword = $Passwords[$i]
                if(-not $DisableCertificateAuthentication)
                {
                    $AssetOutputs = Get-HPiLOAssetTag -Server $AssetIP -Username $AssetUsername -Password $AssetPassword -ErrorAction SilentlyContinue
                    if($Error-match "Invalid input for including both single and double quotes")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidInputWithQuotes+= $IPS[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidInputWithQuotes+=$IPS[$i]
                        }
                        continue
                    }
                }
                else
                {
                    $AssetOutputs = Get-HPiLOAssetTag -Server $AssetIP -Username $AssetUsername -Password $AssetPassword -DisableCertificateAuthentication -ErrorAction SilentlyContinue
                    if($Error-match "Invalid input for including both single and double quotes")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidInputWithQuotes+= $IPS[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidInputWithQuotes+=$IPS[$i]
                        }
                        continue
                    }
                }
                if($Error.Count -eq 0)
                {
                    [Array]$ReturnArray.IPs += $IPs[$i]
                    [Array]$ReturnArray.Usernames += $Usernames[$i]
                    [Array]$ReturnArray.Passwords += $Passwords[$i]                     
                }
                else
                {
                    if($Error -match "The server certificate is not valid.")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidCertificateInput+= $IPs[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidCertificateInput+=$IPs[$i]
                        }
                        $WarningVariable = $IPs[$i]
                        $WarningVariable += " Skipped due to Invalid Certificate."
                        Write-Warning $WarningVariable
                    }
                }
            }
            else
            {
                [String]$AssetIP = $IPs[$i]
                [String]$AssetUsername = $Usernames
                [String]$AssetPassword = $Passwords
                if(-not $DisableCertificateAuthentication)
                {
                    $AssetOutputs = Get-HPiLOAssetTag -Server $AssetIP -Username $AssetUsername -Password $AssetPassword -ErrorAction SilentlyContinue
                    if($Error-match "Invalid input for including both single and double quotes")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidInputWithQuotes+= $IPS[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidInputWithQuotes+=$IPS[$i]
                        }
                        continue
                    }
                }
                else
                {
                    $AssetOutputs = Get-HPiLOAssetTag -Server $AssetIP -Username $AssetUsername -Password $AssetPassword -DisableCertificateAuthentication -ErrorAction SilentlyContinue
                    if($Error-match "Invalid input for including both single and double quotes")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidInputWithQuotes+= $IPS[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidInputWithQuotes+=$IPS[$i]
                        }
                        continue
                    }
                }
                if($Error.Count -eq 0)
                {
                    [Array]$ReturnArray.IPs += $IPs[$i]
                    [Array]$ReturnArray.Usernames += $Usernames
                    [Array]$ReturnArray.Passwords += $Passwords                     
                }
                else
                {
                    if($Error -match "The server certificate is not valid.")
                    {
                        if(($IPS[$i] -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IPS[$i])) -and ($IPS[$i].contains(":")))
                        {
                            $Script:InvalidCertificateInput+= $IPs[$i].Split(":")[0].Trim()
                        }
                        else
                        {
                            $Script:InvalidCertificateInput+=$IPs[$i]
                        }
                        $WarningVariable = $IPs[$i]
                        $WarningVariable += " Skipped due to Invalid Certificate."
                        Write-Warning $WarningVariable
                    }
                }
            }
        }
        return $ReturnArray
    }

    ## -------------------------------------------------------------------------------------------------------------
    ##                    FUNCTION TO CHECK WHETHER INPUT IPv4 IS VALID OR NOT
    ##                     Returns the total number of "." in an IPv4 address
    ##               For example: if input $strIP is "1...1", the return value is 3
    ## -------------------------------------------------------------------------------------------------------------
   
    function Get-IPv4-Dot-Num{
        param (
            [parameter(Mandatory=$true)] [String] $strIP
        )
        [int]$dotnum = 0
        for($i=0;$i -lt $strIP.Length; $i++)
        {
            if($strIP[$i] -eq '.')
            {
                $dotnum++
            }
        }
    
        return $dotnum
    }

    ## -------------------------------------------------------------------------------------------------------------
    ##                       COMPLETES ALL SECTIONS OF ONE IPv4 ADDRESS 
    ##      $arrayforip returns an array with 4 items, which map to the 4 sections of IPv4 address. 
    ##      For example, if input $strIP="x", the $arrayforip will be @("x","0-255","0-255","0-255")
    ## -------------------------------------------------------------------------------------------------------------
    
    function Complete-IPv4{
        param (
            [parameter(Mandatory=$true)] [String] $strIP
        )
        $arrayfor = @()
        $arrayfor += "0-255"
        $arrayfor += "0-255"
        $arrayfor += "0-255"
        $arrayfor += "0-255"

        #with the new format, 1..., or .1, at most 5 items in $sections, but might have empty values  
        $sections = $strIP.Split(".")
			 
	    #no "." in it
        if($sections.length -eq 1)
        {              
            $arrayfor[0]=$sections[0]					
	    }
	    #might have empty item when input is "x." or ".x"
	    elseif($sections.length -eq 2)
	    {
            if($sections[0] -ne '')
            {
                $arrayfor[0]=$sections[0]
                if($sections[1] -ne '')
                {
                    $arrayfor[1]=$sections[1]   
                }
            }
            else
            {
                if($sections[1] -ne '')
                {
                     $arrayfor[3]=$sections[1]
                }
            }				
        }
        elseif($sections.length -eq 3) 
	    {
		    #"1..", "1.1.","1.1.1" "1..1"
            if($sections[0] -ne '')
            {
                $arrayfor[0]=$sections[0]
                if($sections[1] -ne '')
                {
                    $arrayfor[1]=$sections[1]
                    if($sections[2] -ne '')
                    {
                        $arrayfor[2]=$sections[2]
                    }
                }
                else
                {
                    if($sections[2] -ne '')
                    {
                        $arrayfor[3]=$sections[2]
                    }
                }
            }                                
            else
            { 
			    #.1.1
                if($sections[2] -ne '') 
                {
                    $arrayfor[3]=$sections[2]
                    if($sections[1] -ne '')
                    {
                        $arrayfor[2]=$sections[1]
                    }                                      
                }
                else
                {
				    #the 1 and 3 items are empty ".1."
                    if($sections[1] -ne '')
                    {
                        $arrayfor[1]=$sections[1]
                    }
                }
            }							
        }
		#1.1.1., 1..., ...1, 1...1, .x.x.x, x..x.x, x.x..x,..x. 
        elseif($sections.length -eq 4)
	    {
			#1st is not empty
            if($sections[0] -ne '')
            {
                $arrayfor[0]=$sections[0]
		        #2nd is not empty
                if($sections[1] -ne '')
                {
                    $arrayfor[1]=$sections[1]
				    #3rd is not empty
                    if($sections[2] -ne '')
                    {
                        $arrayfor[2]=$sections[2]
					    #4th is not empty
                        if($sections[3] -ne '')
                        {
                            $arrayfor[3]=$sections[3]
                        }
                    }
					#3rd is empty 1.1..1
                    else 
                    {
					    #4th is not empty
                        if($sections[3] -ne '')
                        {
                            $arrayfor[3]=$sections[3]
                        }                            
                    }
                }
				#2nd is empty, 1..1., 1...
                else 
                {
				    #4th is not empty
                    if($sections[3] -ne '')
                    {
                        $arrayfor[3]=$sections[3]
					    #3rd is not empty
                        if($sections[2] -ne '')
                        {
                            $arrayfor[2]=$sections[2]
                        }  
                    }  
					#4th is empty
                    else 
                    {
					    #3rd is not empty
                        if($sections[2] -ne '')
                        {
                            $arrayfor[2]=$sections[2]
                        } 
                    }                        
                }
            }
			#1st is empty
            else 
            {
				#4th is not empty
                if($sections[3] -ne '')
                {
                    $arrayfor[3]=$sections[3]
				    #3rd is not empty
                    if($sections[2] -ne '')
                    {
                        $arrayfor[2]=$sections[2]
						#2rd is not empty
                        if($sections[1] -ne '')
                        {
                            $arrayfor[1]=$sections[1]
                        }                            
                    }
                    else
                    {
					    #2rd is not empty
                        if($sections[1] -ne '')
                        {
                            $arrayfor[1]=$sections[1]
                        }  
                    }
                }
				#4th is empty .1.1., ..1., .1..
                else 
                {
					#3rd is not empty
                    if($sections[2] -ne '')
                    {
                        $arrayfor[2]=$sections[2]                                                      
                    }
						
					#2nd is not empty
                    if($sections[1] -ne '')
                    {
                        $arrayfor[1]=$sections[1]                                                      
                    }
                }                    
            }			
	    }
		#x.x.x.., ..x.x.x, x.x.x.x
        elseif($sections.length -eq 5) 
		{
			#1st is not empty
			if($sections[0] -ne '')
            {
                $arrayfor[0]=$sections[0]
                if($sections[1] -ne '') 
                {
                    $arrayfor[1]=$sections[1]
                }
                if($sections[2] -ne '') 
                {
                    $arrayfor[2]=$sections[2]
                }
                if($sections[3] -ne '') 
                {
                    $arrayfor[3]=$sections[3]
                }
            }

			#1st is empty
            else 
            {                    
                if($sections[4] -ne '')
                {
                    $arrayfor[3]=$sections[4]
                }
                if($sections[3] -ne '') 
                {
                    $arrayfor[2]=$sections[3]
                }
                if($sections[2] -ne'')
                {
                    $arrayfor[1]=$sections[2]
                }
                if($sections[1] -ne '') 
                {
                    $arrayfor[0]=$sections[1]
                }
            }		
	    }

        #$arrayforip.Value = $arrayfor;
        return $arrayfor[0]+"."+$arrayfor[1]+"."+$arrayfor[2]+"."+$arrayfor[3]
    }


    ## -------------------------------------------------------------------------------------------------------------
    ##                            COMPLETE ALL SECTIONS FOR ONE IPv6 ADDRESS
    ## $arrayforip returns an array with 8 or more items, which map to the sections of IPv6 address. 
    ## For example, if input $strIP="x:x:x", the $arrayforip will be @("x","x","x","0-FFFF","0-FFFF","0-FFFF","0-FFFF","0-FFFF")                     FUNTION TO RETRIEVE IPs WHICH HAVE A VALID CERTIFICATE   
    ## -------------------------------------------------------------------------------------------------------------
    
    function Complete-IPv6{
        param (
            [parameter(Mandatory=$true)] [String] $strIP,
            [parameter(Mandatory=$false)] [Int] $MaxSecNum=8
            )
            $arrayfor = @()
            $arrayfor+=@("0-FFFF")
            $arrayfor+=@("0-FFFF")
            $arrayfor+=@("0-FFFF")
            $arrayfor+=@("0-FFFF")
            $arrayfor+=@("0-FFFF")
            $arrayfor+=@("0-FFFF")
			
			#used for ipv4-mapped,also used for ipv6 if not in ipv4 mapped format
            $arrayfor+=@("0-FFFF") 
			
			#used for ipv4-mapped,also used for ipv6 if not in ipv4 mapped format
            $arrayfor+=@("0-FFFF") 
			
			#used for ipv4-mapped
            $arrayfor+=@("") 
			
			#used for ipv4-mapped
            $arrayfor+=@("")  
			
			#used for %
            $arrayfor+=@("") 
			
            #$strIP = $strIP -replace "::", "|" 
            $returnstring=""
			
			#have % in it 
            if($strIP.LastIndexOf("%") -ne -1)  
            {
                $sections = $strIP.Split("%")
                $arrayfor[10]="%"+$sections[1]
                $strIP=$sections[0]                
            }
            #it could have ::, :, %, . inside it, have ipv4 in it
            if($strIP.IndexOf(".") -ne -1) 
            {  
                [int]$nseperate = $strIP.LastIndexOf(":")	
				#to get the ipv4 part				
                $mappedIpv4 = $strIP.SubString($nseperate + 1) 
				#$secarray=@()
                $ipv4part = Complete-IPv4 -strIP $mappedIpv4                				
				
				#to get the first 6 sections
                $strIP = $strIP.Substring(0, $nseperate + 1)  
                $ipv6part = Complete-IPv6 -strIP $strIP -MaxSecNum 6 
                $returnstring += $ipv6part+":"+$ipv4part
            }
			#no ipv4 part in it, to get the 8 sections
            else 
            {
                $doubleColonFound = $null
				#it could have ::,: inside it  
                if($strIP.Contains("::"))
                {           
                    $strIP = $strIP -replace "::", "|"
                    $doubleColonFound = $true 
                }
                
                #$strIP = $strIP -replace "::", "|" 
                $parsedipv6sections=@()
				#suppose to get a 2 element array
                $bigsections = $strIP.Split("|") 
				#no :: in it
                if($bigsections.Length -eq 1) 
                {
                    $parsedipv6sections = $bigsections[0].Split(":")
                    for($x=0; ($x -lt $parsedipv6sections.Length) -and ($x -lt $MaxSecNum); $x++)
                    {
                        $arrayfor[$x] = $parsedipv6sections[$x]
                    }
                }
                elseif($bigsections.Length -gt 1)
                {
					#starting with ::
                    if(($bigsections[0] -eq "")) 
                    {
                        $parsedipv6sections = $bigsections[1].Split(":")
                        $Y=$MaxSecNum-1
                        for($x=$parsedipv6sections.Length; ($parsedipv6sections[$x-1] -ne "") -and ($x -gt 0) -and ($y -gt -1); $x--, $y--)
                        {
                            $arrayfor[$y] = $parsedipv6sections[$x-1]
                        }
                        for(; $y -gt -1; $y--)
                        {
                            $arrayfor[$y]="0"
                        }
                        
                    }
					#not starting with ::, may in the middle or in the ending
                    else 
                    {
                        $parsedipv6sections = $bigsections[0].Split(":")
                        $x=0
                        for(; ($x -lt $parsedipv6sections.Length) -and ($x -lt $MaxSecNum); $x++)
                        {
                            $arrayfor[$x] = $parsedipv6sections[$x]
                        }
                        
                        $y=$MaxSecNum-1
                        if($bigsections[1] -ne "")
                        {
                            $parsedipv6sections2 = $bigsections[1].Split(":")                            
                            for($z=$parsedipv6sections2.Length;  ($parsedipv6sections2[$z-1] -ne "")-and ($z -gt 0) -and ($y -gt ($x-1)); $y--,$z--)
                            {
                                $arrayfor[$y] = $parsedipv6sections2[$z-1]
                            }
                        }
                        for(;$x -lt ($y+1); $x++)
                        {
                              $arrayfor[$x]="0" 
                        }
                    }
                }

                if($MaxSecNum -eq 6)
                {
                    $returnstring = $returnstring = $arrayfor[0]+":"+$arrayfor[1]+":"+$arrayfor[2]+":"+$arrayfor[3]+":"+$arrayfor[4]+":"+$arrayfor[5]
                }
                if($MaxSecNum -eq 8)
                {
                    $appendingstring=""
                    if($arrayfor[8] -ne "")
                    {
                        $appendingstring=":"+$arrayfor[8]
                    }
                    if($arrayfor[9] -ne "")
                    {
                        if($appendingstring -ne "")
                        {
                            $appendingstring = $appendingstring + ":"+$arrayfor[9]
                        }
                        else
                        {
                            $appendingstring=":"+$arrayfor[9]
                        }
                    }
                    if($arrayfor[10] -ne "")
                    {
                        if($appendingstring -ne "")
                        {
                            $appendingstring = $appendingstring + $arrayfor[10]
                        }
                        else
                        {
                            $appendingstring=$arrayfor[10]
                        }
                    }
                
                    $returnstring = $arrayfor[0]+":"+$arrayfor[1]+":"+$arrayfor[2]+":"+$arrayfor[3]+":"+$arrayfor[4]+":"+$arrayfor[5]+":"+$arrayfor[6]+":"+$arrayfor[7]+$appendingstring
                }
            }
            return $returnstring
    }

    ## -------------------------------------------------------------------------------------------------------------
    ## A common function for both IPv4/IPv6 , which will firstly make sure all the sections of IPv4/IPv6 is complete before calling this function)   
    ## input is a IPv4 address(separeated by ".") or IPv6 address(separeated by ":") and in each section, there might be "," and "-", like "1,2,3-4"
    ## return the array of all the possible IP adreesses parsed from the input string
    ## -------------------------------------------------------------------------------------------------------------


    function Get-IPArrayFromString {
        param (
            [parameter(Mandatory=$true)][String] $stringIP,
            [parameter(Mandatory=$false)] [ValidateSet("IPv4","IPv6")] [String]$IPType = "IPv4",
            [parameter(Mandatory=$false)] [String]$PreFix = "",
            [parameter(Mandatory=$false)] [String]$PostFix = ""
        )

        try
        {
            $errMsg = "Invalid format of IP string $stringIP to get $IPType array"
            $IPSectionArray = New-Object System.Collections.ArrayList
            $returnarray = New-Object 'System.Collections.ObjectModel.Collection`1[System.String]'

            $IPdelimiter="."
            if($IPType -eq "IPv6")
            {
                $IPdelimiter=":"
            }
    
            $sections_bycolondot = $stringIP.Split($IPdelimiter)
            for($x=0; ($x -lt $sections_bycolondot.Length -and ($null -ne $sections_bycolondot[$x] -and $sections_bycolondot[$x] -ne "")) ; $x++)
            {
                $section=@()		
                $section= Get-IPArrayFromIPSection -stringIPSection $sections_bycolondot[$x] -IPType $IPType
                $x=$IPSectionArray.Add($section)        
            }
    
            if($IPSectionArray.Count -eq 1)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$PostFix)
                }
            }
            if($IPSectionArray.Count -eq 2)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$PostFix)
                    }
                }
            }
            if($IPSectionArray.Count -eq 3)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$PostFix)
                        }
                    }
                }
            }
            if($IPSectionArray.Count -eq 4)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {  
                                $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$PostFix)
                            }
                        }
                    }
                }
            }

            if($IPSectionArray.Count -eq 5)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {
                                for($b=0; $b -lt $IPSectionArray[4].Count; $b++)
                                {
                                    $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$IPdelimiter+$IPSectionArray[4][$b]+$PostFix)
                                }
                            }
                        }
                    }
                }
            }

            if($IPSectionArray.Count -eq 6)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {
                                for($b=0; $b -lt $IPSectionArray[4].Count; $b++)
                                {
                                    for($c=0; $c -lt $IPSectionArray[5].Count; $c++)
                                    {
                                        $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$IPdelimiter+$IPSectionArray[4][$b]+$IPdelimiter+$IPSectionArray[5][$c]+$PostFix)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if($IPSectionArray.Count -eq 7)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {
                                for($b=0; $b -lt $IPSectionArray[4].Count; $b++)
                                {
                                    for($c=0; $c -lt $IPSectionArray[5].Count; $c++)
                                    {
                                        for($d=0; $d -lt $IPSectionArray[6].Count; $c++)
                                        {
                                            $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$IPdelimiter+$IPSectionArray[4][$b]+$IPdelimiter+$IPSectionArray[5][$c]+$IPdelimiter+$IPSectionArray[6][$d]+$PostFix)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if($IPSectionArray.Count -eq 8)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {
                                for($b=0; $b -lt $IPSectionArray[4].Count; $b++)
                                {
                                    for($c=0; $c -lt $IPSectionArray[5].Count; $c++)
                                    {
                                        for($d=0; $d -lt $IPSectionArray[6].Count; $d++)
                                        {
                                            for($e=0; $e -lt $IPSectionArray[7].Count; $e++)
                                            {
                                                $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$IPdelimiter+$IPSectionArray[4][$b]+$IPdelimiter+$IPSectionArray[5][$c]+$IPdelimiter+$IPSectionArray[6][$d]+$IPdelimiter+$IPSectionArray[7][$e]+$PostFix)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if($IPSectionArray.Count -eq 9)
            {
                for($x=0; $x -lt $IPSectionArray[0].Count; $x++)
                {
                    for($y=0; $y -lt $IPSectionArray[1].Count; $y++)
                    {
                        for($z=0; $z -lt $IPSectionArray[2].Count; $z++)
                        {
                            for($a=0; $a -lt $IPSectionArray[3].Count; $a++)
                            {
                                for($b=0; $b -lt $IPSectionArray[4].Count; $b++)
                                {
                                    for($c=0; $c -lt $IPSectionArray[5].Count; $c++)
                                    {
                                        for($d=0; $d -lt $IPSectionArray[6].Count; $c++)
                                        {
                                            for($e=0; $e -lt $IPSectionArray[7].Count; $e++)
                                            {
                                                for($f=0; $f -lt $IPSectionArray[8].Count; $f++)
                                                {
                                                    $returnarray.Add($PreFix+$IPSectionArray[0][$x]+$IPdelimiter+$IPSectionArray[1][$y]+$IPdelimiter+$IPSectionArray[2][$z]+$IPdelimiter+$IPSectionArray[3][$a]+$IPdelimiter+$IPSectionArray[4][$b]+$IPdelimiter+$IPSectionArray[5][$c]+$IPdelimiter+$IPSectionArray[6][$d]+$IPdelimiter+$IPSectionArray[7][$e]+$IPdelimiter+$IPSectionArray[8][$f]+$PostFix)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            Write-Error $_.Exception.Message.ToString()
        }

        return ,$returnarray
    }

   function Get-IPArrayFromIPSection {
      param (
        [parameter(Mandatory=$true)][String] $stringIPSection,
        [parameter(Mandatory=$false)] [ValidateSet("IPv4","IPv6")] [String]$IPType = "IPv4"
    )
       
    $returnarray=@()   
    try
    {
        $errMsg = "Failed to get $IPType array from IP section $stringIPSection"
        $by_commas = $stringIPSection.split(",")

        if($IPType -eq "IPV4")
        {
            foreach($by_comma in $by_commas)
            {
                $by_comma_dashs = $by_comma.split("-")
                $by_comma_dash_ele=[int]($by_comma_dashs[0])
                $by_comma_dash_ele_end = [int]($by_comma_dashs[$by_comma_dashs.Length-1])
                if($by_comma_dash_ele -gt $by_comma_dash_ele_end)
                {
                    $by_comma_dash_ele = $by_comma_dash_ele_end
                    $by_comma_dash_ele_end = [int]($by_comma_dashs[0])                   
                }

                for(; $by_comma_dash_ele -le $by_comma_dash_ele_end;$by_comma_dash_ele++)
                {
                    $returnarray+=[String]($by_comma_dash_ele)
                
                }
            }
        }

        if($IPType -eq "IPv6")
        {
            foreach($by_comma in $by_commas)
            {
                $by_comma_dashs = $by_comma.split("-")
                $by_comma_dash_ele=[Convert]::ToInt32($by_comma_dashs[0], 16)
                $by_comma_dash_ele_end = ([Convert]::ToInt32($by_comma_dashs[$by_comma_dashs.Length-1], 16))
                if($by_comma_dash_ele -gt $by_comma_dash_ele_end)
                {
                    $by_comma_dash_ele = $by_comma_dash_ele_end
                    $by_comma_dash_ele_end = [Convert]::ToInt32($by_comma_dashs[0], 16)                   
                }

                for(; $by_comma_dash_ele -le $by_comma_dash_ele_end;$by_comma_dash_ele++)
                {
                    $returnarray+=[Convert]::ToString($by_comma_dash_ele,16);
                
                }
            }
        }
    }
    catch
    {
         Write-Error $_.Exception.Message.ToString()
    }
    return ,$returnarray
   }


    ## -------------------------------------------------------------------------------------------------------------
    ##                     FUNTION FOR IPV6 SUPPORT
    ## -------------------------------------------------------------------------------------------------------------

    function Get-IPv6FromString {
          param (
            [parameter(Mandatory=$true)][String] $stringIP,
	        [parameter(Mandatory=$false)] [switch] $AddSquare
	  
            )
            $percentpart=""
            $ipv4array=@()
            $returnstring = New-Object 'System.Collections.ObjectModel.Collection`1[System.String]'
            $ipv6array = New-Object 'System.Collections.ObjectModel.Collection`1[System.String]'
			$preFix=""
			$postFix=""
			if($AddSquare)
			{
				$preFix="["
				$postFix="]"
			}
            try
            {
            $errMsg = "Invalid format of IP string $stringIP to get IPv6 address"
            #it could have ::, :,., % inside it, have % in it            
            if($stringIP.LastIndexOf("%") -ne -1)  
            {
                $sections = $stringIP.Split("%")
                $percentpart="%"+$sections[1]
                $stringIP=$sections[0]                
            }

            #it could have ::, :,.inside it, have ipv4 in it
            if($stringIP.IndexOf(".") -ne -1) 
            {
                [int]$nseperate = $stringIP.LastIndexOf(":")
				#to get the ipv4 part
                $mappedIpv4 = $stringIP.SubString($nseperate + 1) 
				$ipv4array=Get-IPArrayFromString -stringIP $mappedIpv4 -IPType "IPV4" 

                #to get the first 6 sections, including :: or :
				$stringIP = $stringIP.Substring(0, $nseperate + 1) 
            }

            $stringIP = $stringIP -replace "::", "|"
            $sectionsby_2colon=@()
			#suppose to get a 2 element array
            $sectionsby_2colon = $stringIP.Split("|") 
			#no :: in it
            if($sectionsby_2colon.Length -eq 1) 
            {
                $ipv6array=Get-IPArrayFromString -stringIP $sectionsby_2colon[0] -IPType "IPv6" 
            }
            elseif($sectionsby_2colon.Length -gt 1)
            {
			    #starting with ::
                if(($sectionsby_2colon[0] -eq "")) 
                {
                    if(($sectionsby_2colon[1] -eq ""))
                    {
                        $ipv6array=@("::")
                    }
                    else
                    {
                        $ipv6array=Get-IPArrayFromString -stringIP $sectionsby_2colon[1] -IPType "IPv6" -PreFix "::"
                    }
                }
				#not starting with ::, may in the middle or in the ending
                else 
                {
                    if(($sectionsby_2colon[1] -eq ""))
                    {
                        $ipv6array=Get-IPArrayFromString -stringIP $sectionsby_2colon[0] -IPType "IPv6" -PostFix "::"
                    }
                    else
                    {
                        $ipv6array1=Get-IPArrayFromString -stringIP $sectionsby_2colon[0] -IPType "IPv6"  -PostFix "::"                            
                        $ipv6array2=Get-IPArrayFromString -stringIP $sectionsby_2colon[1] -IPType "IPv6" 
                        foreach($x1 in $ipv6array1)
                        {
                            foreach($x2 in $ipv6array2)
                            {
                                $ipv6array.Add($x1 + $x2)
                            }
                        }
                    }                        
                }
            }        

            foreach($ip1 in $ipv6array)
            {
                if($ipv4array.Count -ge 1)
                {
                    foreach($ip2 in $ipv4array)
                    {
                        if($ip1.SubString($ip1.Length-1) -eq ":")
                        {
                            $returnstring.Add($preFix+$ip1+$ip2+$percentpart+$postFix)
                        }
                        else
                        {
                            $returnstring.Add($preFix+$ip1+":"+$ip2+$percentpart+$postFix)
                        }
                    }
                }
                else
                {
                    $returnstring.Add($preFix+$ip1+$percentpart+$postFix)
                }            
            }
        }
        catch
        {
            Write-Error $_.Exception.Message.ToString()
        }
        return $returnstring    
    }


    ## -------------------------------------------------------------------------------------------------------------
    ##                     FUNTION TO RETRIEVE SYSTEM INVENTORY DATA USING iLO CMDLETS
    ##               Find-HPiLO, Get-HPiLOHealthSummary,Get-HPiLOERSSetting, Get-HPiLOFirmwareInfo  
    ## -------------------------------------------------------------------------------------------------------------
    Function GetData
    {
        Param (
            [Array]$iLOIP,
            [Array]$iLOUsername,
            [Array]$iLOPassword,
            [switch]$DisableCertificateAuthentication 
        )

        #Header for the output csv file
    
        $Header = "iLOIP,Server S/N,Model,System Health,Power Supply,Power Supply Status,IRS Register,iLO FW,System ROM,Smart Array,Dynamic Smart Array,Smart HBA,HP Ethernet Adapter,Intelligent Platform Abstraction Data,Power Management Controller Firmware,Power Management Controller FW Bootloader,SAS Programmable Logic Device,Server Platform Services (SPS) Firmware,System Programmable Logic Device,Redundant System ROM,TPM Firmware"
        $HeaderArray = @(
                        "iLO","System ROM", "Smart Array",
                        "Dynamic Smart Array","Smart HBA","HP Ethernet","Intelligent Platform Abstraction Data",
                        "Power Management Controller Firmware","Power Management Controller FW Bootloader",
                        "SAS Programmable Logic Device","Server Platform Services (SPS) Firmware",
                        "System Programmable Logic Device","Redundant System ROM","TPM Firmware"

                        )
        Set-content -Path $script:SystemInventoryFile -Value $Header
        $ipv6_one_section="[0-9A-Fa-f]{1,4}"
        $ipv6_one_section_phen="$ipv6_one_section(-$ipv6_one_section)?"
	    $ipv6_one_section_phen_comma="$ipv6_one_section_phen(,$ipv6_one_section_phen)*"

        $ipv4_one_section="(2[0-4]\d|25[0-5]|[01]?\d\d?)"
	    $ipv4_one_section_phen="$ipv4_one_section(-$ipv4_one_section)?"
	    $ipv4_one_section_phen_comma="$ipv4_one_section_phen(,$ipv4_one_section_phen)*"

        $ipv4_regex_inipv6="${ipv4_one_section_phen_comma}(\.${ipv4_one_section_phen_comma}){3}"  
        $ipv4_one_section_phen_comma_dot_findhpilo="(\.\.|\.|${ipv4_one_section_phen_comma}|\.${ipv4_one_section_phen_comma}|${ipv4_one_section_phen_comma}\.)"

        $port_regex = ":([1-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])"
	    $ipv6_regex_findhpilo="^\s*(${ipv4_regex_inipv6}|${ipv6_one_section_phen_comma}|((${ipv6_one_section_phen_comma}:){1,7}(${ipv6_one_section_phen_comma}|:))|((${ipv6_one_section_phen_comma}:){1,6}(:${ipv6_one_section_phen_comma}|${ipv4_regex_inipv6}|:))|((${ipv6_one_section_phen_comma}:){1,5}(((:${ipv6_one_section_phen_comma}){1,2})|:${ipv4_regex_inipv6}|:))|((${ipv6_one_section_phen_comma}:){1,4}(((:${ipv6_one_section_phen_comma}){1,3})|((:${ipv6_one_section_phen_comma})?:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1,3}(((:${ipv6_one_section_phen_comma}){1,4})|((:${ipv6_one_section_phen_comma}){0,2}:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1,2}(((:${ipv6_one_section_phen_comma}){1,5})|((:${ipv6_one_section_phen_comma}){0,3}:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1}(((:${ipv6_one_section_phen_comma}){1,6})|((:${ipv6_one_section_phen_comma}){0,4}:${ipv4_regex_inipv6})|:))|(:(((:${ipv6_one_section_phen_comma}){1,7})|((:${ipv6_one_section_phen_comma}){0,5}:${ipv4_regex_inipv6})|:)))(%.+)?\s*$" 
	    $ipv6_regex_findhpilo_with_bra ="^\s*\[(${ipv4_regex_inipv6}|${ipv6_one_section_phen_comma}|((${ipv6_one_section_phen_comma}:){1,7}(${ipv6_one_section_phen_comma}|:))|((${ipv6_one_section_phen_comma}:){1,6}(:${ipv6_one_section_phen_comma}|${ipv4_regex_inipv6}|:))|((${ipv6_one_section_phen_comma}:){1,5}(((:${ipv6_one_section_phen_comma}){1,2})|:${ipv4_regex_inipv6}|:))|((${ipv6_one_section_phen_comma}:){1,4}(((:${ipv6_one_section_phen_comma}){1,3})|((:${ipv6_one_section_phen_comma})?:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1,3}(((:${ipv6_one_section_phen_comma}){1,4})|((:${ipv6_one_section_phen_comma}){0,2}:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1,2}(((:${ipv6_one_section_phen_comma}){1,5})|((:${ipv6_one_section_phen_comma}){0,3}:${ipv4_regex_inipv6})|:))|((${ipv6_one_section_phen_comma}:){1}(((:${ipv6_one_section_phen_comma}){1,6})|((:${ipv6_one_section_phen_comma}){0,4}:${ipv4_regex_inipv6})|:))|(:(((:${ipv6_one_section_phen_comma}){1,7})|((:${ipv6_one_section_phen_comma}){0,5}:${ipv4_regex_inipv6})|:)))(%.+)?\]($port_regex)?\s*$" 	
        $ipv4_regex_findhpilo="^\s*${ipv4_one_section_phen_comma_dot_findhpilo}(\.${ipv4_one_section_phen_comma_dot_findhpilo}){0,3}($port_regex)?\s*$"

  		
        #Step2 - Show progress of Determing if Input is IP address or Hostname
        $Step       = 2
        $StepText   = "Determing if Input is IP address or Hostname ..."    
        Write-Progress -Id $Id -Activity $Activity -Status (&$StatusBlock) -PercentComplete ($Step / $TotalSteps * 100)

        $IsIPAddress = $null
        $IsIPv4Address = $null
        $IsIPv6Address = $null
        $InputIPv4Array = @()
        $InputIPv6Array = @()
        foreach($IP in $iLOIP)
        {      
            if(
                (($IP -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IP))) -or
                (($IP -match $ipv6_regex_findhpilo -or $IP -match $ipv6_regex_findhpilo_with_bra) -and
                 (-not ($IP.contains("]") -and $IP.Split("]")[0].Replace("[","").Trim() -match $ipv4_regex_findhpilo))
                )
              )
            {
                if(($IP -match $ipv4_regex_findhpilo) -and (4 -ge (Get-IPv4-Dot-Num -strIP  $IP)))
                {
                    $InputIPv4Array += $IP
                    $IsIPv4Address = $true
                }
                elseif($IP -match $ipv6_regex_findhpilo -or $IP -match $ipv6_regex_findhpilo_with_bra)
                {
                    $InputIPv6Array += $IP            
                    $IsIPv6Address = $true
                }
                if($IsIPAddress -eq $false)
                {
                    Write-Host "Enter all IP Addresses or all HostNames in the Input."
                    Return
                }
                $IsIPAddress = $true
            }
           
            else  #suppose to be host name
            {
                if($IsIPAddress -eq $true)
                {
                    Write-Host "Enter all IP Addresses or all HostNames in the Input."
                    Return
                }
                $IsIPAddress = $false
                try
	            {
		            #if hostname is "1", it returns "0.0.0.1" and the uploadstring later will hang
		            $dns = [System.Net.Dns]::GetHostAddresses($IP)
		            [Array]$IPFromHost += [string]$dns.IPAddressToString
	            }
	            catch
	            {
                    Write-Host "Invalid Hostname: IP Address translation not available for hostname $IP."
                    Write-Host "$_.Exception"
                }							             
            }
        }

        ## -------------------------------------------------------------------------------------------------------------
        ##                      DETERMINE ALL THE IPs IN THE GIVEN INPUT
        ##               In case of Range,it gives an array of all the IPs in that range
        ## -------------------------------------------------------------------------------------------------------------
        
        if($InputIPv4Array.Length -gt 0)
        {
            $IPv4Array = New-Object System.Collections.ArrayList              
            foreach($inputIP in $InputIPv4Array)
            {
                if($inputIP.contains(":"))
                {
                      $returnip = Complete-IPv4 -strIP $inputIP.Split(":")[0].Trim()     
                }
                else
                {
                    $returnip = Complete-IPv4 -strIP $inputIP
                }
                $x = $IPv4Array.Add($returnip)
             }
        }

        if($InputIPv6Array.Length -gt 0)
        {
                $IPv6Array = New-Object System.Collections.ArrayList        
            foreach($inputIP in $InputIPv6Array)
            { 
                if($inputIP.contains("]")) #[ipv6] and [ipv6]:port
                {
                    $returnip = Complete-IPv6 -strIP $inputIP.Split("]")[0].Replace("[","").Trim()
                    $returnip = "[" + $returnip + "]" + $inputIP.Split("]")[1].Trim()
                }
                else #ipv6 without [] nor port
                {
                    $returnip = Complete-IPv6 -strIP $inputIP 
                    $returnip = "[" + $returnip + "]"
                }
                $x = $IPv6Array.Add($returnip)
            }
        }   

	    $iptoping = New-Object System.Collections.ArrayList
	    if($IsIPAddress)
	    {	
            foreach($ipv4 in $IPv4Array)
            { 
                if($ipv4.contains(":")) #contains port
                {
                    $retarray = Get-IPArrayFromString -stringIP $ipv4.Split(":")[0].Trim() -IPType "IPv4"
                    foreach($oneip in $retarray)
                    {
                        $x = $ipToPing.Add($oneip + ":" + $ipv4.Split(":")[1].Trim())
                    }                 
                }
                else
                {
                    $retarray = Get-IPArrayFromString -stringIP $ipv4 -IPType "IPv4"
                    foreach($oneip in $retarray)
                    {
                        $x = $ipToPing.Add($oneip)
                    }  
                }                  
            }
				
            foreach($ipv6 in $IPv6Array) #all ipv6 has been changed to [ipv6] or [ipv6]:port
            { 
                $retarray = Get-IPv6FromString -stringIP $ipv6.Split("]")[0].Replace("[","").Trim() 
                foreach($oneip in $retarray)
                {
                    $x = $ipToPing.Add($oneip)
                }                           
            }		
        }
        

        #Step3 - Show progress of Determing Valid IPs
        $Step       = 3
        $StepText   = "Determing Valid IPs in the Input....."    
        Write-Progress -Id $Id -Activity $Activity -Status (&$StatusBlock) -PercentComplete ($Step / $TotalSteps * 100)

        [Array]$InputIPs=$null
        [Array]$InputUsernames=$null
        [Array]$InputPasswords=$null
        Write-Verbose "Executing Find-HPiLO"
        if(-not $IsIPAddress)#For iLO IP
        {
            [Array]$IpsWithiLO2iLO5  = $null
            if($IPFromHost.Count -ne 0)
            {
                [Array]$FindiLOOutput = Find-HPiLO -Range $IPFromHost -ErrorAction SilentlyContinue
                if(($FindiLOOutput -ne $null) -and ($FindiLOOutput.Count -ne 0))
				{
					$IpsWithiLO2iLO5 =  $FindiLOOutput | where {$_.PN.Contains("iLO 2") -or $_.PN.Contains("iLO 5")} 
					$FindiLOOutput =  $FindiLOOutput | where {$_.PN.Contains("iLO 3") -or $_.PN.Contains("iLO 4")}
				}
            }
            else
            {
                Write-Host "No valid IPs found for the specified Hostnames."
                return
            }
            Write-Verbose "Validating certificates for the given IPs."
            [Array]$ReturnArray = Get-ValidIPs -IPs $FindiLOOutput.HOSTNAME -Usernames $iLOUsername -Passwords $iLOPassword
            $IPFromHostName = @()
            foreach($ReturnIP in $ReturnArray.IPs)
            {
                $dns = [System.Net.Dns]::GetHostAddresses($ReturnIP)
                $IPFromHostName+= [string]$dns.IPAddressToString
            }
            if($IPFromHostName.Count -ne 0)
            {
                [Array]$FindiLOOutput = Find-HPiLO -Range $IPFromHostName -WarningAction SilentlyContinue
            }
            <#else
            {
                 Write-Host "No valid IPs found for the specified Hostnames."
                 return  
            }#>
            $InputIPs = $ReturnArray.IPs
            $InputUsernames = $ReturnArray.Usernames
            $InputPasswords = $ReturnArray.Passwords
        }
        else
        {
            [Array]$ReturnArray = $null

            [Array]$NotRangeIPs
            $RangeMatch = $iLOIP -match $ipv4_regex_findhpilo
            $RangeMatch += ($iLOIP -match $ipv6_regex_findhpilo)|Where-Object { $RangeMatch -notcontains $_ }
            $RangeMatch += ($iLOIP -match $ipv6_regex_findhpilo_with_bra)|Where-Object { $RangeMatch -notcontains $_ }

            if($RangeMatch -eq $null)
            {
                if($iLOIP -ne 0)
                {
                    [Array]$FindiLOOutput = Find-HPiLO -Range $iLOIP
                }
                else
                {
                    Write-Host "No Valid IPs found."
                    Return
                }
                Write-Verbose "Validating certificates for the given IPs."
                [Array]$ReturnArray = Get-ValidIPs -IPs $FindiLOOutput.IP -Usernames $iLOUsername -Passwords $iLOPassword
                if($ReturnArray.IPs -ne 0)
                {
                    [Array]$FindiLOOutput = Find-HPiLO -Range $ReturnArray.IPs -WarningAction SilentlyContinue
                }
                else
                {
                    Write-Host "No valid IPs found."
                    return
                }
                $InputIPs = $ReturnArray.IPs
                $InputUsernames = $ReturnArray.Usernames
                $InputPasswords = $ReturnArray.Passwords            
            }
            else
            {      
                #mulltiple Ip ranges with a single USername or password
                if(($iLOIP.Count -gt 1) -and ($iLOUsername.Count -eq 1))
                {
                   $InputUsernames = $iLOUsername
                   $InputPasswords = $iLOPassword
                }
                [Array]$ReturnArray = $null
                Write-Verbose "Validating certificates for the given IPs."
                [Array]$Script:IpsWithiLO2iLO5 = $null
                [Array]$tempiLO2iLO5 = $null
                for($j=0;$j -lt $RangeMatch.Count; $j++)
                {
                    
                    [Array]$tempArray = Find-HPiLO -Range $iLOIP[$j] -WarningAction SilentlyContinue
       
                    if($null -ne $tempArray)
                    {
                   
                      $IpsWithiLO3iLO4 =  $tempArray | where {$_.PN.Contains("iLO 3") -or $_.PN.Contains("iLO 4")} 
                      $tempiLO2iLO5 =  $tempArray | where {$_.PN.Contains("iLO 2") -or $_.PN.Contains("iLO 5")} 
                      if($null -ne $tempiLO2iLO5)
                      {
                            $Script:IpsWithiLO2iLO5 +=$tempiLO2iLO5.IP
                      }
                      $tempArray = $IpsWithiLO3iLO4
                      $ReturnArray1 = @()
                      if(($iLOIP[$j] -match $ipv4_regex_findhpilo) -and ($iLOIP[$j] -match $port_regex))
                      {
                        if(($iLOIP.Count -gt 1) -and ($iLOUsername.Count -eq 1))
                        {
                            $ReturnArray1 = Get-ValidIPs -IPs $iLOIP[$j] -Usernames $iLOUsername -Passwords $iLOPassword
                        }
                        else
                        {
                            $ReturnArray1 = Get-ValidIPs -IPs $iLOIP[$j] -Usernames $iLOUsername[$j] -Passwords $iLOPassword[$j]
                        }
                      }
                      else
                      {
                
                        if(($iLOIP.Count -gt 1) -and ($iLOUsername.Count -eq 1))
                        {
                             $ReturnArray1 = Get-ValidIPs -IPs $tempArray.IP -Usernames $iLOUsername -Passwords $iLOPassword
                        }
                        else
                        {
                             $ReturnArray1 = Get-ValidIPs -IPs $tempArray.IP -Usernames $iLOUsername[$j] -Passwords $iLOPassword[$j]
                        }
                      }
                      if(($ReturnArray1 -ne $null) -and ($ReturnArray1.Count -ne 0))
                      {
                        [Array]$ReturnArray += $ReturnArray1
                      }
                      [Array]$tempArray = $null
                      if(($ReturnArray1 -ne $null) -and ($ReturnArray1.Count -ne 0))
                      {
                          $tempArray = Find-HPiLO -Range $ReturnArray1.IPs -WarningAction SilentlyContinue
                          if( $null -ne $tempArray)
                          {
                              if(($iLOIP[$j] -match $ipv4_regex_findhpilo) -and ($iLOIP[$j] -match $port_regex))
                              {
                                  $InputIPs += $iLOIP[$j]
                              }
                              else
                              {
                                  $InputIPs += $tempArray.IP
                              }
                              [Array]$FindiLOOutput += $tempArray
                              if(-not (($iLOIP.Count -gt 1) -and ($iLOUsername.Count -eq 1)))
                              {
                                  foreach($item in $ReturnArray1.IPs)
                                  {
                                      $InputUsernames += $iLOUsername[$j]
                                      $InputPasswords += $iLOPassword[$j] 
                                  }
                               }
                            }
                        }
                    }
                }
            }
        }

       $InputIPv4Array = @()
       $InputIPv6Array = @()
        foreach($r in $InputIPs)
        {            
            if(($r -match $ipv4_regex_findhpilo)  -and (4 -ge (Get-IPv4-Dot-Num -strIP  $r)) )
            {
                $InputIPv4Array += $r                
            }
            elseif($r -match $ipv6_regex_findhpilo -or $r -match $ipv6_regex_findhpilo_with_bra)
            {
                $InputIPv6Array += $r
            }                    
       }
       if(($IPv4Array -ne $null) -and ($IPv4Array.Count -ne 0) )
       {
            $IPv4Array.Clear()
       }
       if(($IPv6Array -ne $null) -and ($IPv6Array.Count -ne 0) )
       {
            $IPv6Array.Clear()
       }
       if($InputIPv4Array.Length -gt 0)
        {
            $IPv4Array = New-Object System.Collections.ArrayList              
            foreach($inputIP in $InputIPv4Array)
            {
                if($inputIP.contains(":"))
                {
                    $returnip = Complete-IPv4 -strIP $inputIP.Split(":")[0].Trim()
                    #$returnip = $returnip + ":" + $inputIP.Split(":")[1].Trim()      
                }
                else
                {
                    $returnip = Complete-IPv4 -strIP $inputIP
                }
                $x = $IPv4Array.Add($returnip)
            }
        }

        if($InputIPv6Array.Length -gt 0)
        {
            $IPv6Array = New-Object System.Collections.ArrayList        
            foreach($inputIP in $InputIPv6Array)
            { 
                if($inputIP.contains("]")) #[ipv6] and [ipv6]:port
                {
                    $returnip = Complete-IPv6 -strIP $inputIP.Split("]")[0].Replace("[","").Trim()
                    $returnip = "[" + $returnip + "]" + $inputIP.Split("]")[1].Trim()
                }
                else #ipv6 without [] nor port
                {
                    $returnip = Complete-IPv6 -strIP $inputIP 
                    $returnip = "[" + $returnip + "]"
                }
                $x = $IPv6Array.Add($returnip)
            }
        } 
        $inputIPToCompare = New-Object System.Collections.ArrayList
        foreach($ipv4 in $IPv4Array)
        { 
            if($ipv4.contains(":")) #contains port
            {
               $retarray = Get-IPArrayFromString -stringIP $ipv4.Split(":")[0].Trim() -IPType "IPv4"
               foreach($oneip in $retarray)
               {
                  $x = $inputIPToCompare.Add($oneips)
               }                 
            }
            else
            {
               $retarray = Get-IPArrayFromString -stringIP $ipv4 -IPType "IPv4"
               foreach($oneip in $retarray)
               {
                  $x = $inputIPToCompare.Add($oneip)
               }  
            }                  
        }
				
        foreach($ipv6 in $IPv6Array) #all ipv6 has been changed to [ipv6] or [ipv6]:port
        { 
           $retarray = Get-IPv6FromString -stringIP $ipv6.Split("]")[0].Replace("[","").Trim() 
           foreach($oneip in $retarray)
           {
              $x = $inputIPToCompare.Add($oneip)
           }                           
        }

        if($IsIPAddress)
        {
            $NotReachableIPs = $iptoping |Where-Object { $inputIPToCompare -notcontains $_ }         
        }
        else
        {
            $NotReachableIPs = $iLOIP |Where-Object { $InputIPs -notcontains $_ }
        }  
        $NotReachableIPs = $NotReachableIPs |Where-Object {$IpsWithiLO2iLO5 -notcontains $_ }
        $NotReachableIPs = $NotReachableIPs |Where-Object {$script:InvalidInputWithQuotes -notcontains $_ }
        $NotReachableIPs = $NotReachableIPs |Where-Object {$script:InvalidCertificateInput -notcontains $_ }    		
        
        if($script:InvalidInputWithQuotes.Count -ne 0)
        {
            Write-Host "Invalid Credentials/Invalid Input was given for following IPs:"
            $script:InvalidInputWithQuotes
        }
        if($Script:InvalidCertificateInput.Count -ne 0)
        {
            Write-Host "Following IPs were skipped due to invalid certificate:"
            $script:InvalidCertificateInput
        }
        if($NotReachableIPs.Count -ne 0)
        {
            Write-Host "Following IPs were unreachable:"
            $NotReachableIPs
        }
        if($InputIPs.Count -eq 0)
        {
            return
        }     		
        

       #Step4 - Show progress of Retrieving Data Using HPiLOCmdlets
       $Step       = 4
       $StepText   = "Retrieving Data Using HPiLOCmdlets....."    
       Write-Progress -Id $Id -Activity $Activity -Status (&$StatusBlock) -PercentComplete ($Step / $TotalSteps * 100)
       if($DisableCertificateAuthentication)
       {
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOHealthSummary"
            [Array]$HealthSummaryOutput = Get-HPiLOHealthSummary -Server $InputIPs -Username $InputUsernames -Password $InputPasswords -DisableCertificateAuthentication
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOPowerSupply"
            [Array]$PowerSUpplyOutput = Get-HPiLOPowerSupply -Server $InputIPs -Username $InputUsernames -Password $InputPasswords -DisableCertificateAuthentication
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOERSSetting"
            [Array]$ERSSettingOutput = Get-HPiLOERSSetting -Server $InputIPs -Username $InputUsernames -Password $InputPasswords -DisableCertificateAuthentication
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOFirmwareInfo"
            [Array]$FirmwareInfoOutput = Get-HPiLOFirmwareInfo -Server $InputIPs -Username $InputUsernames -Password $InputPasswords -DisableCertificateAuthentication
            sleep -Milliseconds 2000
        }
        else
        {
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOHealthSummary"
            [Array]$HealthSummaryOutput = Get-HPiLOHealthSummary -Server $InputIPs -Username $InputUsernames -Password $InputPasswords
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOPowerSupply"
            [Array]$PowerSUpplyOutput = Get-HPiLOPowerSupply -Server $InputIPs -Username $InputUsernames -Password $InputPasswords
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOERSSetting"
            [Array]$ERSSettingOutput = Get-HPiLOERSSetting -Server $InputIPs -Username $InputUsernames -Password $InputPasswords
            sleep -Milliseconds 2000
            Write-Verbose "Executing Get-HPiLOFirmwareInfo"
            [Array]$FirmwareInfoOutput = Get-HPiLOFirmwareInfo -Server $InputIPs -Username $InputUsernames -Password $InputPasswords 
            sleep -Milliseconds 2000
        }


        #Incase of IPv6, assigning IPs without zeros

        #if($IsIPv6Address)
        #{
            $FindiLOOutput | where {$_.IP -notmatch $ipv4_regex_findhpilo} | ForEach-Object {$_.IP = $InputIPs[$FindiLOOutput.IndexOf($_)]}
        #}
        #Step5 - Creating Output file with system Inventory Details....
        $Step       = 5
        $StepText   = "Creating Output file with system Inventory Details.... "    
        Write-Progress -Id $Id -Activity $Activity -Status (&$StatusBlock) -PercentComplete ($Step / $TotalSteps * 100)
        
        for($i=0; $i -lt $FindiLOOutput.IP.Count; $i++)
        {
            if($HealthSummaryOutput[$i].IP -eq $FindiLOOutput[$i].IP)
            {
                continue
            }
            else
            {      
                [Array]$tempOutputArray = $null
                for($j=0;$j -lt $i;$j++)
                {
                    [Array]$tempOutputArray += $HealthSummaryOutput[$j]
                }
                [Array]$tempOutputArray += ""
                for($j=$i+1;$j -lt $HealthSummaryOutput.Count;$j++)
                {
                    [Array]$tempOutputArray += $HealthSummaryOutput[$j]
                }
                $HealthSummaryOutput = $tempOutputArray 
            }
        }
        for($i=0; $i -lt $FindiLOOutput.IP.Count; $i++)
        {
            if($PowerSUpplyOutput[$i].IP -eq $FindiLOOutput[$i].IP)
            {
                continue
            }
            else
            {  
                [Array]$tempOutputArray = $null
                for($j=0;$j -lt $i;$j++)
                {
                    $tempOutputArray += $PowerSUpplyOutput[$j]
                }
                $tempOutputArray += ""
                for($j=$i+1;$j -lt $PowerSUpplyOutput.Count;$j++)
                {
                    $tempOutputArray += $PowerSUpplyOutput[$j]
                }
                $PowerSUpplyOutput = $tempOutputArray
            }
        }
        for($i=0; $i -lt $FindiLOOutput.IP.Count; $i++)
        {
            if($ERSSettingOutput[$i].IP -eq $FindiLOOutput[$i].IP)
            {
                continue
            }
            else
            {
                [Array]$tempOutputArray = $null
                for($j=0;$j -lt $i;$j++)
                {
                    $tempOutputArray += $ERSSettingOutput[$j]
                }
                $tempOutputArray += ""
                for($j=$i+1;$j -lt $ERSSettingOutput.Count;$j++)
                {
                    $tempOutputArray += $ERSSettingOutput[$j]
                }
                $ERSSettingOutput = $tempOutputArray
            }
        }
        for($i=0; $i -lt $FindiLOOutput.IP.Count; $i++)
        {
            if($FirmwareInfoOutput[$i].IP -eq $FindiLOOutput[$i].IP)
            {
                continue
            }
            else
            {
                [Array]$tempOutputArray = $null
                for($j=0;$j -lt $i;$j++)
                {
                    $tempOutputArray += $FirmwareInfoOutput[$j]
                }
                $tempOutputArray += ""
                for($j=$i+1;$j -lt $FirmwareInfoOutput.Count;$j++)
                {
                    $tempOutputArray += $FirmwareInfoOutput[$j]
                }
                $FirmwareInfoOutput = $tempOutputArray
            }
        }
        
        Write-Verbose "Generating the Output"
        #Concatenating the properties in $output
        for($i=0; $i -lt $ReturnArray.IPs.Count; $i++)
        {            
            if($IsIPAddress)
            {
                [String]$output += $FindiLOOutput[$i].IP+","+$FindiLOOutput[$i].SerialNumber+","+$FindiLOOutput[$i].SPN+","
            }
            else
            {
                [String]$output += $FindiLOOutput[$i].HOSTNAME+","+$FindiLOOutput[$i].SerialNumber+","+$FindiLOOutput[$i].SPN+","
            }


            if($HealthSummaryOutput[$i] -eq "")
            {
                $output += "EXCEPTION" + ","
            }
            elseif($HealthSummaryOutput[$i] -ne $null)
            {
                if(($HealthSummaryOutput[$i].STATUS_TYPE.Equals("OK")) -and ($HealthSummaryOutput[$i].BIOS_HARDWARE_STATUS -ne $null))
                {    
                    $output += $HealthSummaryOutput[$i].BIOS_HARDWARE_STATUS + ","
                }
                elseif($HealthSummaryOutput[$i].STATUS_MESSAGE.Equals("Login failed."))
                {
                    $output += "LOGIN FAILED" + ","
                }
                elseif($HealthSummaryOutput[$i].STATUS_TYPE.Equals("ERROR"))
                {
                    $output += "ERROR" + ","
                }
                elseif($HealthSummaryOutput[$i].BIOS_HARDWARE_STATUS -eq $null)
                {
                    $output += "N/A" + ","
                } 
            }
            else
            {
                $output += "N/A" + ","
            }


            if($PowerSUpplyOutput[$i] -eq "")
            {
                $output += "EXCEPTION" + ","
            }
            elseif($PowerSUpplyOutput[$i] -ne $null )
            {
                if($PowerSUpplyOutput[$i].STATUS_MESSAGE.Equals("Login failed."))
                {    
                    $output += "LOGIN FAILED" + ","
                }
                elseif($PowerSUpplyOutput[$i].STATUS_TYPE.Equals("ERROR"))
                {
                    $output += "ERROR" + ","
                }
                elseif($PowerSUpplyOutput[$i].supply.label -eq $null)
                {
                    $output += "N/A" + ","
                }
                else
                {
                    $labels = $PowerSUpplyOutput[$i].supply.label
                    foreach($label in $labels)
                    {
	                    $output+=$label + ";"
                    }
                    $output = $output.TrimEnd(";")
                    $output+=","
                }  
            }
            else
            {
                $output += "N/A" + ","
            }

                       
            
            if($HealthSummaryOutput[$i] -eq "")
            {
                $output += "EXCEPTION" + ","
            }
            elseif($HealthSummaryOutput[$i] -ne $null)
            {
                if($HealthSummaryOutput[$i].STATUS_MESSAGE.Equals("Login failed."))
                {    
                    $output += "LOGIN FAILED" + ","
                }
                elseif($HealthSummaryOutput[$i].POWER_SUPPLIES_STATUS -ne $null)
                {
	                $output += $HealthSummaryOutput[$i].POWER_SUPPLIES_STATUS + ","
                }
                elseif(($HealthSummaryOutput[$i].POWER_SUPPLIES.REDUNDANCY -ne $null) -and ($HealthSummaryOutput[$i].POWER_SUPPLIES.REDUNDANCY.Contains("Redundant")))
                {
	                $output += $HealthSummaryOutput[$i].POWER_SUPPLIES.STATUS + ","
                }
                elseif(($HealthSummaryOutput[$i].POWER_SUPPLIES.REDUNDANCY -ne $null) -and ($HealthSummaryOutput[$i].POWER_SUPPLIES.REDUNDANCY.Contains("Not Redundant")))
                {
	                $output += $HealthSummaryOutput[$i].POWER_SUPPLIES.REDUNDANCY + ","
                }
                elseif($HealthSummaryOutput[$i].STATUS_TYPE.Equals("ERROR"))
                {
                    $output += "ERROR" + ","
                }
                else
                {
                    $output += "N/A" + ","
                }
            }
            else
            {
                $output += "N/A" + ","
            }


            if($ERSSettingOutput[$i] -eq "")
            {
                $output += "EXCEPTION" + ","
            }
            elseif($ERSSettingOutput[$i] -ne $null)
            {
                if($ERSSettingOutput[$i].STATUS_TYPE.Equals("OK"))
                {
                    if($ERSSettingOutput[$i].ERS_STATE -eq 1)
                    {
                        $output += "Yes"+","
                    }
                    elseif($ERSSettingOutput[$i].ERS_STATE -eq 0)
                    {
                        $output += "No"+","
                    }
                    else
                    {
                        $output += "N/A"+","
                    }
                }
                elseif($ERSSettingOutput[$i].STATUS_MESSAGE.Equals("Login failed."))
                {
                    $output += "LOGIN FAILED" + ","
                }
                elseif($ERSSettingOutput[$i].STATUS_TYPE.Equals("ERROR"))
                {
                    $output += "ERROR" + ","
                }
                else
                {
                    $output += "N/A" + ","
                }
            }
            else
            {
                $output += "N/A"+","
            }


            if($FirmwareInfoOutput[$i] -eq "")
            {
                $output += "EXCEPTION`n"
            }
            elseif(($FirmwareInfoOutput[$i] -ne $null) -and ($FirmwareInfoOutput[$i].STATUS_MESSAGE.Equals("Login failed.")))
            {
                $output += "LOGIN FAILED`n"
            }
            elseif($FirmwareInfoOutput[$i].STATUS_TYPE.Equals("ERROR"))
            {
                $output += "ERROR" + "`n"
            }
            elseif($FirmwareInfoOutput[$i].FirmwareInfo -ne $null)
            {
            
               [Array]$FirmwareInfo = $FirmwareInfoOutput[$i].FirmwareInfo 

                if($FirmwareInfoOutput[$i].STATUS_TYPE.Equals("OK"))
                {
                    for($j=0; $j -lt $HeaderArray.Count; $j++ )
                    {
                        $HeaderFound = $false
                        for($k=0; $k -lt $FirmwareInfo.Count; $k++ )
                        {
                            if($HeaderArray[$j].Contains("Dynamic Smart Array") -or $HeaderArray[$j].Contains("Smart HBA") -or $HeaderArray[$j].Contains("HP Ethernet") -or $HeaderArray[$j].Contains("Smart Array"))
                            {
                                if($FirmwareInfo[$k].FIRMWARE_NAME -match $HeaderArray[$j]) 
                                {
                                    $output+=$FirmwareInfo[$k].FIRMWARE_VERSION + "(" + $FirmwareInfo[$k].FIRMWARE_NAME.Substring($HeaderArray[$j].Length) + ")" + ","
                                    $HeaderFound = $true
                                    break
                                }
                            }
                            elseif($HeaderArray[$j].Contains("Power Management Controller FW Bootloader"))
                            {
                                if($FirmwareInfo[$k].FIRMWARE_NAME -match "Power Management Controller\s\w*\sBootloader") 
                                {
                                    $output+=$FirmwareInfo[$k].FIRMWARE_VERSION + ","
                                    $HeaderFound = $true
                                    break
                                }
                            }
                            elseif($HeaderArray[$j].Contains("System ROM"))
                            {
                                if($FirmwareInfo[$k].FIRMWARE_NAME.Contains("System ROM") -or
                                $FirmwareInfo[$k].FIRMWARE_NAME.Contains("HP ProLiant System ROM")
                                ) 
                                {
                                    $output+=$FirmwareInfo[$k].FIRMWARE_VERSION + ","
                                    $HeaderFound = $true
                                    break
                                }
                            }
                            else
                            {
                                if($FirmwareInfo[$k].FIRMWARE_NAME -eq $HeaderArray[$j]) 
                                {
                                    $output+=$FirmwareInfo[$k].FIRMWARE_VERSION + ","
                                    $HeaderFound = $true
                                    break
                                }
                            }
                        }
                    
                        if(-not $HeaderFound)
                        {
                            $output+="N/A"+","
                        }
                    }
                    $output += "`n"  
                }
            }
            else
            {
                $output += "`n"
            }
        }
        Add-content -Path $script:SystemInventoryFile -Value $output
        Write-Progress -Id $Id -Completed -Activity $Activity
    }


    $Activity = "System Inventory Tool Progress"
    $Id       = 1    
    $TotalSteps = 5
    $StatusText = '"Step $($Step.ToString().PadLeft($TotalSteps.Count.ToString().Length)) of $TotalSteps | $StepText"'
    $StatusBlock = [ScriptBlock]::Create($StatusText) 

    #Step1 - Show progress of Prerequisities
    $Step       = 1
    $StepText   = "Checking Prerequisities ..."    
    Write-Progress -Id $Id -Activity $Activity -Status (&$StatusBlock) -PercentComplete ($Step / $TotalSteps * 100) 
   
    #Validate Output csv file path
    if(-not $OutputCSV)
    {
        $TimeStamp = get-date -format ddMMMyyyyhhmmss 
        $script:SystemInventoryFile  = "SystemInventory_$TimeStamp.csv"
        write-host "Output File path is not given. Output file will be created in the current directory."
    }
    elseif([IO.Path]::GetExtension($OutputCSV) -ne ".csv")
    {
        $TimeStamp = get-date -format ddMMMyyyyhhmmss
        $script:SystemInventoryFile  = "SystemInventory_$TimeStamp.csv"
        write-host "Output File path is not valid. Output file will be created in the current directory."
    }
    else
    {
       $script:SystemInventoryFile  = $OutputCSV
    }
     
    if (-not (test-path $Script:SystemInventoryFile))
    {
       $SystemInventoryCSV = New-Item $script:SystemInventoryFile  -type file -force
    }
    [Environment]::CurrentDirectory = pwd
    $OutputFileFullPath = [IO.Path]::GetFullPath($script:SystemInventoryFile)
    Write-Host "Output file path -> $OutputFileFullPath"

    switch ($PSCmdlet.ParameterSetName)
    {

        "CommandLine" 
        {
            if ( -not( [string]::IsNullOrEmpty($iLOUsername) -or [string]::IsNullOrEmpty($iLOPassword) ))
            {
                if($DisableCertificateAuthentication)
                {
                    GetData -iLOIP $iLOIP -iLOUsername $iLOUsername -iLOPassword $iLOPassword -DisableCertificateAuthentication
                }
                else
                {
                    GetData -iLOIP $iLOIP -iLOUsername $iLOUsername -iLOPassword $iLOPassword
                }
            }
            else
            {
                write-host " ILO Username and Password are not specified." 
            }
        }

        "CSVInput"
        {
            #Validate Input csv file path
            if ( -not $InputiLOCSV)
            {
                write-host "Input CSV file is not specified for the parameter InputiLOCSV."
                return
            }
            if ( -not (Test-path $InputiLOCSV) )
            {
                write-host "File $InputiLOCSV does not exist."
                return
            }
            if([IO.Path]::GetExtension($InputiLOCSV) -ne ".csv")
            {
                write-host "Specify the full path of the input csv."
                return
            }

  
            $ListofServers = import-csv $InputiLOCSV
            if($DisableCertificateAuthentication)
            {
                GetData -iLOIP $ListofServers.IP -iLOUsername $ListofServers.Username -iLOPassword $ListofServers.Password -DisableCertificateAuthentication 
            }
            else
            {
                GetData -iLOIP $ListofServers.IP -iLOUsername $ListofServers.Username -iLOPassword $ListofServers.Password
            }
        }
    }
# SIG # Begin signature block
# MIIjpgYJKoZIhvcNAQcCoIIjlzCCI5MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAv8vv4QvIufIJi
# A3CkSQDLpd2kj3yu9EAX14LUmShxOaCCHrIwggPuMIIDV6ADAgECAhB+k+v7fMZO
# WepLmnfUBvw7MA0GCSqGSIb3DQEBBQUAMIGLMQswCQYDVQQGEwJaQTEVMBMGA1UE
# CBMMV2VzdGVybiBDYXBlMRQwEgYDVQQHEwtEdXJiYW52aWxsZTEPMA0GA1UEChMG
# VGhhd3RlMR0wGwYDVQQLExRUaGF3dGUgQ2VydGlmaWNhdGlvbjEfMB0GA1UEAxMW
# VGhhd3RlIFRpbWVzdGFtcGluZyBDQTAeFw0xMjEyMjEwMDAwMDBaFw0yMDEyMzAy
# MzU5NTlaMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwS
# CtgleZEiVypv3LgmxENza8K/LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3
# Te2/tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwF
# eEWlL4nO55nn/oziVz89xpLcSvh7M+R5CvvwdYhBnP/FA1GZqtdsn5Nph2Upg4XC
# YBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+nw54trorqpuaqJxZ9YfeYcRG8
# 4lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+VMET
# fMV58cnBcQIDAQABo4H6MIH3MB0GA1UdDgQWBBRfmvVuXMzMdJrU3X3vP9vsTIAu
# 3TAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
# ZS5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADA/BgNVHR8EODA2MDSgMqAwhi5odHRw
# Oi8vY3JsLnRoYXd0ZS5jb20vVGhhd3RlVGltZXN0YW1waW5nQ0EuY3JsMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIBBjAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMTANBgkqhkiG9w0BAQUFAAOBgQADCZuP
# ee9/WTCq72i1+uMJHbtPggZdN1+mUp8WjeockglEbvVt61h8MOj5aY0jcwsSb0ep
# rjkR+Cqxm7Aaw47rWZYArc4MTbLQMaYIXCp6/OJ6HVdMqGUY6XlAYiWWbsfHN2qD
# IQiOQerd2Vc/HXdJhyoWBl6mOGoiEqNRGYN+tjCCBKMwggOLoAMCAQICEA7P9DjI
# /r81bgTYapgbGlAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzIwHhcNMTIxMDE4MDAwMDAwWhcNMjAx
# MjI5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgU2lnbmVyIC0gRzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCi
# Yws5RLi7I6dESbsO/6HwYQpTk7CY260sD0rFbv+GPFNVDxXOBD8r/amWltm+YXkL
# W8lMhnbl4ENLIpXuwitDwZ/YaLSOQE/uhTi5EcUj8mRY8BUyb05Xoa6IpALXKh7N
# S+HdY9UXiTJbsF6ZWqidKFAOF+6W22E7RVEdzxJWC5JH/Kuu9mY9R6xwcueS51/N
# ELnEg2SUGb0lgOHo0iKl0LoCeqF3k1tlw+4XdLxBhircCEyMkoyRLZ53RB9o1qh0
# d9sOWzKLVoszvdljyEmdOsXF6jML0vGjG/SLvtmzV4s73gSneiKyJK4ux3DFvk6D
# Jgj7C72pT5kI4RAocqrNAgMBAAGjggFXMIIBUzAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBzBggrBgEFBQcBAQRn
# MGUwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA3
# BggrBgEFBQcwAoYraHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vdHNzLWNh
# LWcyLmNlcjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vdHMtY3JsLndzLnN5bWFu
# dGVjLmNvbS90c3MtY2EtZzIuY3JsMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBU
# aW1lU3RhbXAtMjA0OC0yMB0GA1UdDgQWBBRGxmmjDkoUHtVM2lJjFz9eNrwN5jAf
# BgNVHSMEGDAWgBRfmvVuXMzMdJrU3X3vP9vsTIAu3TANBgkqhkiG9w0BAQUFAAOC
# AQEAeDu0kSoATPCPYjA3eKOEJwdvGLLeJdyg1JQDqoZOJZ+aQAMc3c7jecshaAba
# tjK0bb/0LCZjM+RJZG0N5sNnDvcFpDVsfIkWxumy37Lp3SDGcQ/NlXTctlzevTcf
# Q3jmeLXNKAQgo6rxS8SIKZEOgNER/N1cdm5PXg5FRkFuDbDqOJqxOtoJcRD8HHm0
# gHusafT9nLYMFivxf1sJPZtb4hbKE4FtAC44DagpjyzhsvRaqQGvFZwsL0kb2yK7
# w/54lFHDhrGCiF3wPbRRoXkzKy57udwgCRNx62oZW8/opTBXLIlJP7nPf8m/PiJo
# Y1OavWl0rMUdPH+S4MO8HNgEdTCCBUwwggM0oAMCAQICEzMAAAA12NVZWwZxQSsA
# AAAAADUwDQYJKoZIhvcNAQEFBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEpMCcGA1UEAxMgTWljcm9zb2Z0IENvZGUgVmVyaWZpY2F0aW9u
# IFJvb3QwHhcNMTMwODE1MjAyNjMwWhcNMjMwODE1MjAzNjMwWjBvMQswCQYDVQQG
# EwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4
# dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBD
# QSBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt/caM+byAAQt
# OeBOW+0fvGwPzbX6I7bO3psRM5ekKUx9k5+9SryT7QMa44/P5W1QWtaXKZRagLBJ
# etsulf24yr83OC0ePpFBrXBWx/BPP+gynnTKyJBU6cZfD3idmkA8Dqxhql4Uj56H
# oWpQ3NeaTq8Fs6ZxlJxxs1BgCscTnTgHhgKo6ahpJhiQq0ywTyOrOk+E2N/On+Fp
# b7vXQtdrROTHre5tQV9yWnEIN7N5ZaRZoJQ39wAvDcKSctrQOHLbFKhFxF0qfbe0
# 1sTurM0TRLfJK91DACX6YblpalgjEbenM49WdVn1zSnXRrcKK2W200JvFbK4e/vv
# 6V1T1TRaJwIDAQABo4HQMIHNMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB
# /wQIMAYBAf8CAQIwHQYDVR0OBBYEFK29mHo0tCb3+sQmVO8DveAky1QaMAsGA1Ud
# DwQEAwIBhjAfBgNVHSMEGDAWgBRi+wohW39DbhHaCVRQa/XSlnHxnjBVBgNVHR8E
# TjBMMEqgSKBGhkRodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNyb3NvZnRDb2RlVmVyaWZSb290LmNybDANBgkqhkiG9w0BAQUFAAOC
# AgEANiui8uEzH+ST9/JphcZkDsmbYy/kcDeY/ZTse8/4oUJG+e1qTo00aTYFVXoe
# u62MmUKWBuklqCaEvsG/Fql8qlsEt/3RwPQCvijt9XfHm/469ujBe9OCq/oUTs8r
# z+XVtUhAsaOPg4utKyVTq6Y0zvJD908s6d0eTlq2uug7EJkkALxQ/Xj25SOoiZST
# 97dBMDdKV7fmRNnJ35kFqkT8dK+CZMwHywG2CcMu4+gyp7SfQXjHoYQ2VGLy7BUK
# yOrQhPjx4Gv0VhJfleD83bd2k/4pSiXpBADxtBEOyYSe2xd99R6ljjYpGTptbEZL
# 16twJCiNBaPZ1STy+KDRPII51KiCDmk6gQn8BvDHWTOENpMGQZEjLCKlpwErULQo
# rttGsFkbhrObh+hJTjkLbRTfTAMwHh9fdK71W1kDU+yYFuDQYjV1G0i4fRPleki4
# d1KkB5glOwabek5qb0SGTxRPJ3knPVBzQUycQT7dKQxzscf7H3YMF2UE69JQEJJB
# SezkBn02FURvib9pfflNQME6mLagfjHSta7K+1PVP1CGzV6TO21dfJo/P/epJViE
# 3RFJAKLHyJ433XeObXGL4FuBNF1Uusz1k0eIbefvW+Io5IAbQOQPKtF/IxVlWqyZ
# lEM/RlUm1sT6iJXikZqjLQuF3qyM4PlncJ9xeQIx92GiKcQwggVpMIIEUaADAgEC
# AhBGfXVEDRzPiUVcG3iHohKHMA0GCSqGSIb3DQEBCwUAMH0xCzAJBgNVBAYTAkdC
# MRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQx
# GjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQDExpDT01PRE8gUlNB
# IENvZGUgU2lnbmluZyBDQTAeFw0xNjA4MTkwMDAwMDBaFw0xNzA4MTkyMzU5NTla
# MIHSMQswCQYDVQQGEwJVUzEOMAwGA1UEEQwFOTQzMDQxCzAJBgNVBAgMAkNBMRIw
# EAYDVQQHDAlQYWxvIEFsdG8xHDAaBgNVBAkMEzMwMDAgSGFub3ZlciBTdHJlZXQx
# KzApBgNVBAoMIkhld2xldHQgUGFja2FyZCBFbnRlcnByaXNlIENvbXBhbnkxGjAY
# BgNVBAsMEUhQIEN5YmVyIFNlY3VyaXR5MSswKQYDVQQDDCJIZXdsZXR0IFBhY2th
# cmQgRW50ZXJwcmlzZSBDb21wYW55MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEA5LnGop2du9JJNqVhUqt3H6GIhcJipjG0thgyXRl878NVHnlZjdWSV6ii
# 4jUSEbCpkM9+k5dhyab1ZRhwd07/zDkiDvEsINNTwMoUfxhuIxdQXhb4mfvC0R2A
# N9xV/z6l2A2SzUDNIYwYRoBxpKelGEhRAQ2gWMKopFlj0EfaGP8TBvb+zK0lWhw9
# wL/n5BA4fDTxnek4cfGnL+30pveV225Cku8vwPMRNHgpVN3WuCG+xijTXe7y86YS
# CEgywBuE6fF5T2fJ5zG23OQe190HjL5lJEa/t68fdonIMc+3KZUntxko562tARh8
# DKr+HeC0SSMTprY39Dcw+z07N8NBLwIDAQABo4IBjTCCAYkwHwYDVR0jBBgwFoAU
# KZFg/4pN+uv5pmq4z/nmS71JzhIwHQYDVR0OBBYEFDtfqbsmv7hUs38zb65C74+k
# kaaRMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMBEGCWCGSAGG+EIBAQQEAwIEEDBGBgNVHSAEPzA9MDsGDCsGAQQBsjEB
# AgEDAjArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21vZG8ubmV0L0NQ
# UzBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01P
# RE9SU0FDb2RlU2lnbmluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPgYIKwYBBQUH
# MAKGMmh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET1JTQUNvZGVTaWduaW5n
# Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJ
# KoZIhvcNAQELBQADggEBAGNneiCECLlSBtPk9CaUWppOOyRtO3R1GtQR4iX0Ob13
# AzYF0/Oc3MxyQkTeT9oMm3HwdmIImmfvB/MlpeYOlq7myECfsq9EzGvuXTUYdlmb
# BVuA+svSNq/L5cwkw00fIJVgyUzumjIscWwmiBSH+c3aBHlcg+XHweATmC6k1Jz9
# PqClIK5j+2xb0FcKwdjEV6cZFFMXY0o0d9ywtsIs+/YEtnxvWVd2EAAj3q95+x03
# nYtOOaGFXKBWSR2vs+qXIEdE+DUlqoRWzjCNDkeo7bMUzBRaORCu9+T/UYbitJ9r
# 3koMX6A04jCdfK6OTA+d3+WRYQLuMOYYfGRTotPRg6MwggV0MIIEXKADAgECAhAn
# Zu5W60nzjqvXcKL8hN4iMA0GCSqGSIb3DQEBDAUAMG8xCzAJBgNVBAYTAlNFMRQw
# EgYDVQQKEwtBZGRUcnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwg
# VFRQIE5ldHdvcmsxIjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3Qw
# HhcNMDAwNTMwMTA0ODM4WhcNMjAwNTMwMTA0ODM4WjCBhTELMAkGA1UEBhMCR0Ix
# GzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEa
# MBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0Eg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCR6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2f
# cHK3YX/JSw8Xpz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs
# /Q36nGz637CC9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio
# 5JIk2kNrYrhV/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62
# a+pGx8cgoLEfZd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7g
# UYPDCUZObT6Z+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlW
# Pc9vqv9JWL7wqP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArn
# cevPDt09qZahSL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0
# AuqLZxUpaVICu9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dm
# a/RMhnEw6abfFobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5
# WdYgGq/yapiqcrxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo4H0
# MIHxMB8GA1UdIwQYMBaAFK29mHo0tCb3+sQmVO8DveAky1QaMB0GA1UdDgQWBBS7
# r34CPfqm8TyEjq3uOJjs2TIy1DAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zARBgNVHSAECjAIMAYGBFUdIAAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDov
# L2NybC51c2VydHJ1c3QuY29tL0FkZFRydXN0RXh0ZXJuYWxDQVJvb3QuY3JsMDUG
# CCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0
# LmNvbTANBgkqhkiG9w0BAQwFAAOCAQEAZL+D8V+ahdDNuKEpVw3oWvfR6T7ydgRu
# 8VJwux48/00NdGrMgYIl08OgKl1M9bqLoW3EVAl1x+MnDl2EeTdAE3f1tKwc0Dur
# FxLW7zQYfivpedOrV0UMryj60NvlUJWIu9+FV2l9kthSynOBvxzz5rhuZhEFsx6U
# LX+RlZJZ8UzOo5FxTHxHDDsLGfahsWyGPlyqxC6Cy/kHlrpITZDylMipc6LrBnsj
# nd6i801Vn3phRZgYaMdeQGsj9Xl674y1a4u3b0b0e/E9SwTYk4BZWuBBJB2yjxVg
# WEfb725G/RX12V+as9vYuORAs82XOa6Fux2OvNyHm9Gm7/E7bxA4bzCCBeAwggPI
# oAMCAQICEC58h8wOk0pS/pT9HLfNNK8wDQYJKoZIhvcNAQEMBQAwgYUxCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYDVQQDEyJDT01P
# RE8gUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTEzMDUwOTAwMDAwMFoX
# DTI4MDUwODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENB
# IExpbWl0ZWQxIzAhBgNVBAMTGkNPTU9ETyBSU0EgQ29kZSBTaWduaW5nIENBMIIB
# IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAppiQY3eRNH+K0d3pZzER68we
# /TEds7liVz+TvFvjnx4kMhEna7xRkafPnp4ls1+BqBgPHR4gMA77YXuGCbPj/aJo
# nRwsnb9y4+R1oOU1I47Jiu4aDGTH2EKhe7VSA0s6sI4jS0tj4CKUN3vVeZAKFBhR
# LOb+wRLwHD9hYQqMotz2wzCqzSgYdUjBeVoIzbuMVYz31HaQOjNGUHOYXPSFSmsP
# gN1e1r39qS/AJfX5eNeNXxDCRFU8kDwxRstwrgepCuOvwQFvkBoj4l8428YIXUez
# g0HwLgA3FLkSqnmSUs2HD3vYYimkfjC9G7WMcrRI8uPoIfleTGJ5iwIGn3/VCwID
# AQABo4IBUTCCAU0wHwYDVR0jBBgwFoAUu69+Aj36pvE8hI6t7jiY7NkyMtQwHQYD
# VR0OBBYEFCmRYP+KTfrr+aZquM/55ku9Sc4SMA4GA1UdDwEB/wQEAwIBhjASBgNV
# HRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGA1UdIAQKMAgw
# BgYEVR0gADBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv
# bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB
# AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E
# T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v
# ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAAI/AjnD7vjKO4neDG1NsfFOkk+v
# wjgsBMzFYxGrCWOvq6LXAj/MbxnDPdYaCJT/JdipiKcrEBrgm7EHIhpRHDrU4ekJ
# v+YkdK8eexYxbiPvVFEtUgLidQgFTPG3UeFRAMaH9mzuEER2V2rx31hrIapJ1Hw3
# Tr3/tnVUQBg2V2cRzU8C5P7z2vx1F9vst/dlCSNJH0NXg+p+IHdhyE3yu2VNqPeF
# RQevemknZZApQIvfezpROYyoH3B5rW1CIKLPDGwDjEzNcweU51qOOgS6oqF8H8tj
# OhWn1BUbp1JHMqn0v2RH0aofU04yMHPCb7d4gp1c/0a7ayIdiAv4G6o0pvyM9d1/
# ZYyMMVcx0DbsR6HPy4uo7xwYWMUGd8pLm1GvTAhKeo/io1Lijo7MJuSy2OU4wqjt
# xoGcNWupWGFKCpe0S0K2VZ2+medwbVn4bSoMfxlgXwyaiGwwrFIJkBYb/yud29Ag
# yonqKH4yjhnfe0gzHtdl+K7J+IMUk3Z9ZNCOzr41ff9yMU2fnr0ebC+ojwwGUPuM
# J7N2yfTm18M04oyHIYZh/r9VdOEhdwMKaGy75Mmp5s9ZJet87EUOeWZo6CLNuO+Y
# hU2WETwJitB/vCgoE/tqylSNklzNwmWYBp7OSFvUtTeTRkF8B93P+kPvumdh/31J
# 4LswfVyA4+YWOUunMYIESjCCBEYCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNV
# BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UE
# ChMRQ09NT0RPIENBIExpbWl0ZWQxIzAhBgNVBAMTGkNPTU9ETyBSU0EgQ29kZSBT
# aWduaW5nIENBAhBGfXVEDRzPiUVcG3iHohKHMA0GCWCGSAFlAwQCAQUAoHwwEAYK
# KwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJf5S7mrFrfE
# 4vM6rLyPxr4LMlb+eNqBybrc00keSYwVMA0GCSqGSIb3DQEBAQUABIIBAGO7CcN5
# tknzkQMjud4svelNkDkUMe86iW2wCByJT+GT3LSZ4fMb5czpdEGd03MR6x2jlaBb
# Bs3VsL7KHsM2uABijxRt/w8pNjX3kSrKB5pjfIkeIU7mFnrptvaYwIuS+d7aTBo2
# VjCcKmb4tvFwiCmhyOtbpC3ZdpEvvBAA38axMqlv6kR/5/JP+hD20rPwyK/2Ela1
# KUDPlm0h2j3Pel5fDzN+DDU6vq7X9xWu12RnyMm2gWNmejifJ3ZBC6k2wNL/08qK
# syQ4lVfy9VysYUg+VFzwCgdYI58gfQnsS6ZQrsfPRnZ/TgYJYVyvJSq5ANXvqmui
# PeimQmwq92BdTxOhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcwODA4MDU0OTAwWjAjBgkqhkiG9w0BCQQx
# FgQUyqFLmByKgJUh5ZK7Skzu2uFS6o0wDQYJKoZIhvcNAQEBBQAEggEAK00emrBa
# XwjK5ArCv5j3W9AcGOCc6MB8Sgv2Sqd52idzoiXByUHySDjzNh8MrKiSxwtdgM6g
# kaWNrGQOjFAgPEZ59qzeX23SL+TW/86ExWQFywqynGXUrX5aI86JqENKTRIJfK7f
# e62SRxee1Eyp/dhndbXIBA1hINPP10uDHepr4m7qMKL5hTtu8xuTsb+tS07Hp1Fq
# 6BwBypi4SEwkQ4nzJcR3Zsp0oTsFhH8kR+4EKi2ilXLsEGEgRaDsKA5HNS8F75PP
# GQz+N0gDcLFhc9+QD7SwjONJHzx53frmfEXZXUgEd/9z0m/VFY647o+NwL3o9YFb
# 9GnmKiMeflnvRg==
# SIG # End signature block
