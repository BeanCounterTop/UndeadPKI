[CmdletBinding()]
Param(
  [Parameter(Mandatory=$true,Position=1)][string]$Servername,
  [Parameter(Position=2)][string]$CA_Name = $Servername,
  [Parameter(Position=3)][int]$Days = 30
)



#---------------- User-configurable section ---------------------------------
$DC = "DC=Contoso,DC=Corp"
$dir = "D:\Scripts\PKI\Zombie_CA\Working"
$logfile = "$dir\Zombie_CA.log"
$OpenSSLPath = "D:\Program Files (x86)\GnuWin32\bin\"
#---------------- Don't touch anything below this line ----------------------





    
Import-Module ActiveDirectory
#This checks for the presence of the custom Eventlog source associated with this script. If it's not present, it creates it.
if (!(Test-Path HKLM:SYSTEM\CurrentControlSet\Services\EventLog\Application\Zombie_CA)) {
    New-EventLog -LogName Application -Source Zombie_CA
    }

if ($env:Path -notmatch "GnuWin32") {
    $env:Path += ";$OpenSSLPath"
    }
Set-Location $dir

Function CleanUp {
    Remove-Item "$dir\*" -exclude "*_keys.pem","*.log"
    }

Function ParseCRL ($CRLPath) {
    #This returns a formatted line containing the decoded data of a given CRL.
    $(openssl crl -text -in $CRLPath) -join "`n"
    }

Function WriteFile ($Filename, $Content, $Encoding = [text.encoding]::ascii) {
    #write-host $content
    #This function takes a file path, string, and encoding scheme, and writes the string to the file using the specified encoding (which is ascii by default).  
    # The reason I used this particular method is because the normal methods (out-file, etc) use windows-style line endings ("CRLF"), and OpenSSL prefers Unix-style ("LF")
    $encoding= [System.Text.Encoding]::ASCII
    $uencoding = [System.Text.Encoding]::UNICODE

    [System.Text.Encoding]::Convert([System.Text.Encoding]::UNICODE, $encoding, $uencoding.GetBytes($content)) | % { $aContent += [char]$_}
    $content = $aContent
    [System.IO.File]::WriteAllText($Filename,$Content,$Encoding)
    }

Function StringToHex ($string) {
    #This function accepts a string and returns a string of hex characters separated by colons (ex "00:3A:44:A1:4C...")
    #It also prepends a "length" byte to the string.
    $output = "{0:x2}" -f $string.length
    $String.ToCharArray() |% { [system.string]$Output += ":" + [system.string]::format("{0:X2}",[system.convert]::toUInt32($_)) }
    $output
    }

Function AddIndexLine ([string]$Serial, $RevDate = (get-date), $ReasonCode = "cessationOfOperation") {
    #This generates a line for OpenSSL's certificate database ("index.txt").
    if ($RevDate.GetType().name -eq "String") {
        $Stamp = $(get-date $([datetime]::ParseExact($RevDate, 'MMM d HH:mm:ss yyyy Z', $null, "AllowWhiteSpace").ToUniversalTime()) -format yyMMddhhmmssZ).tostring()
     } elseif ($RevDate.GetType().name -eq "DateTime") {
        $Stamp = (get-date $RevDate -format yyMMddhhmmssZ).tostring()
     } else {
        $Stamp = (get-date -format yyMMddhhmmssZ).tostring() 
     }

     #Herestrings don't like indention.
    $LineString = @"
R`t$Stamp`t$Stamp,$($ReasonCode -replace ' ', '')`t$Serial`tunknown`tnull
"@
    $linestring 
    }

Function FindCRLNumber ($FullData) {
#This scans the current CRL data for the CRL number, and returns it.
    [regex]$CRLNumberRegex = "(?:CRL Number:\s+)([0-9]+)"
    [int]$CRLNumber = $CRLNumberRegex.matches($FullData).groups[1].value
    [int]$CRLNumber
    }

Function ExecuteProcess ([string]$Filename, [string]$Arguments, [string]$LogFile) {
    #This function exists because start-process was implemented in such a way that makes it difficult to get at the output.
    # It outputs a line to a .log defined at the top of the script as well as the eventlog using the "Zombie_CA" source created at the top of the script.
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $FileName
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $pinfo.WorkingDirectory = $dir
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    sleep(1)
    $stderr = $p.StandardError.ReadToEnd()
    $exitcode = $p.exitcode

    #Certutil helpfully provides a "less than zero" exit code in the case of an error, as well as sending the error text to STDOUT.
    if (($exitcode -lt 0) -and ($filename -eq "certutil.exe")) { $stderr = $stdout; $stdout = $null;$exitcode = 1 }
    #Log the execution parameters to file
    "$(get-date -format yyyy-MM-dd.HH:mm:ssz)`tINFO`tServer: $Servername`tCA: $CA_Name`tFile: $Filename`tArgs: $Arguments" | out-file $logfile -Append
    #If things went wrong, send a log entry to file as well as the application log.
    if ($exitcode -ne 0) {
        "$(get-date -format yyyy-MM-dd.HH:mm:ssz)`tERROR`tServer: $Servername`tCA: $CA_Name`tFile: $Filename`tArgs: $Arguments`tError: $($stderr -replace "`r`n", " - ")" | out-file $logfile -Append
        Write-Eventlog -LogName Application -Source Zombie_CA -EntryType Error -EventID 9000 -Message "Server:`t$Servername`nCA:`t$CA_Name`nFile:`t$Filename`nArgs:`t$Arguments`nError:`t$($stderr -replace "`r`n", "`r`n`t")" 
        }
    #If there's some kind of stdout, send it to the text log. This usually only outputs Certutil's success message.
    if ($stdout) {"$(get-date -format yyyy-MM-dd.HH:mm:ssz)`tINFO`tServer: $Servername`tCA: $CA_Name`tFile: $Filename`tArgs: $Arguments`t$($stdout -replace "`r`n", " - ")" | out-file $logfile -Append}
     @{"stdout"=$stdout;"stderr"=$stderr;"exitcode"=$exitcode}
    }

Function GenerateOpenSSLIndex ($FullData) {
    #This function searches the decoded CRL data for named "parameter: value" pairs, then uses AddIndexLine to generate the index.txt file contents.
    [regex]$RevokedRegex = "(?m)Serial Number:\s*(?<SerialNumber>.*)\s*$|Revocation Date:\s*(?<RevocationDate>.*)\s*$"
    $names = @('SerialNumber','RevocationDate')
    $Matches = $RevokedRegex.Matches($FullData)    
    $Revoked = @($(foreach($match in $matches | where Success) {foreach($name in $names) {if($match.Groups[$name].Value) {@{$name = $match.Groups[$name].Value}}}}))
    $index = @()
    for($i=0;$i -lt $revoked.count;$i+=2) {$props = @{};$props += $revoked[$i];$props += $revoked[$i+1]; $index += AddIndexLine $props['SerialNumber'] $props['RevocationDate']}
    $index += ""
    $index -join "`n"
    }
Function GenerateHexTimeStamp ($DaysFromNow) {
    #This function adds $DaysFromNow to the current date and returns a hex-formatted string representing 
    # the MS datestamp format, prepended by a value representing the length of the string.
    $NextPublish = $(get-date).addDays([int]$DaysFromNow)
    $NextPublishTimestamp = $(get-date $($NextPublish) -format yyMMddhhmmss) + "Z"
    StringToHex($NextPublishTimestamp)
}
Function GenerateHexCDPTarget ($CA, $Server, $DomainContext) {
    #This generates a hex string representing the path of a CA's CDP, prepended by a few empty fields with decrementing length bits.
    $CDPTarget = "ldap:///$("CN=$CA,CN=$Server,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainContext" -replace " ","%20")`?certificateRevocationList?base?objectClass=cRLDistributionPoint"
    #write-host $CDPTarget
    $Target = StringToHex($CDPTarget)
    $CDPLength = [convert]::ToInt32(($Target.split(":")[0]),16)
    "30:81:$("{0:X2}" -f  ($CDPLength + 12)):30:81:$("{0:X2}" -f  ($CDPLength + 9)):A0:81:$("{0:X2}" -f  ($CDPLength + 6)):A0:81:$("{0:X2}" -f  ($CDPLength + 3)):86:81:$Target"
    }
Function PullBase64CRLFromLDAP ($CA, $Server, $DomainContext) {
    #This function pulls the current CRL from LDAP and returns a formatted string containing the base64-encoded X509 CRL.
    #Sometimes it just so happens that the last character in the Base64 encoded string isn't a newline, so it checks for that and
    # adds one if necessary..
    $CRLByteArray = $(get-adobject "CN=$CA,CN=$Server,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainContext" -properties certificateRevocationList).certificateRevocationList
    $CRLBase64 = [system.convert]::ToBase64String($CRLByteArray) -replace "(.{64})","`$1`n"
    if ($CRLBase64[$CRLBase64.length -1] -notmatch "`n") {$CRLBase64 += "`n"}
    $X509CRL = $("-----BEGIN X509 CRL-----`n" + $CRLBase64 + "-----END X509 CRL-----`n")
    $X509CRL
    }

#Here's the meat of the script.  This section uses the functions defined above to create an environment suitable for OpenSSL to work in.
# This includes pulling and parsing the current CRL, specifying the contents of the OpenSSL.cnf, populating the index.txt database, 
# and creating the appropriate files.

$HexNextPublishTimestamp = GenerateHexTimeStamp $Days
$HexCDPTarget = GenerateHexCDPTarget $CA_Name $Servername $DC
$CurrentCRL = PullBase64CRLFromLDAP  $CA_Name $Servername $DC
$CurrentCRLPath = "$dir\$Servername.crl"
WriteFile $CurrentCRLPath $CurrentCRL
$ParsedCRL = ParseCRL $CurrentCRLPath
$CRLNumber = FindCRLNumber $ParsedCRL
$OpenSSLIndex = GenerateOpenSSLIndex $ParsedCRL

$HereString = @"
[ ca ]
default_ca	= default
[ default ]
dir		= $dir
RANDFILE	= $dir\openssl.rnd
crl_extensions	= crl_ext
default_crl_days= $days
default_md	= sha1
authorityKeyIdentifier=keyid:always,issuer:always

database	= $Servername`_index.txt
certificate	= $Servername`_keys.pem
crlnumber 	= $Servername`_crlnumber.txt
private_key	= $Servername`_keys.pem

[ crl_ext ]
1.3.6.1.4.1.311.21.1  = DER:02:01:00
1.3.6.1.4.1.311.21.14 = DER:$HexCDPTarget
1.3.6.1.4.1.311.21.4  = DER:17`:$HexNextPublishTimestamp
 
"@

WriteFile "$dir\$Servername`_crlnumber.txt" $("{0:x4}" -f ($CRLNumber+1))
WriteFile "$dir\$Servername`_crlnumber.txt.old" $("{0:x4}" -f $($CRLNumber))
WriteFile "$dir\$Servername`_index.txt.attr" "unique_subject = yes`n"
WriteFile "$dir\$Servername`_index.txt" $OpenSSLindex
WriteFile "$dir\openssl.cnf" $HereString

#Now that the stage is set, these three commands put everything into motion. First we need to use OpenSSL generate the new CRL and 
# convert it to DER format.  Then then push it up to AD using Certutil.  The ExecuteProcess function logs this behavior and retuns
# a hash table containing the exit code, which we can use to exit early should an error occur. If everything goes fine, we'll exit
# and specify a "good" exit code.

$exitcode = 0
$exitcode += $(ExecuteProcess "openssl.exe" "ca -config $dir\openssl.cnf -gencrl -out $dir\$Servername`_new_crl.pem" $logfile).exitcode
if ($exitcode) {CleanUp;[Environment]::Exit(1)}
$exitcode += $(ExecuteProcess "openssl.exe" "crl -inform pem -outform der -in $dir\$Servername`_new_crl.pem -out $dir\$Servername`_new_crl.crl" $logfile).exitcode
if ($exitcode) {CleanUp;[Environment]::Exit(1)}
$exitcode += $(ExecuteProcess "certutil.exe"  "-dspublish $dir\$Servername`_new_crl.crl" $logfile).exitcode
if ($exitcode) {CleanUp;[Environment]::Exit(1)}

CleanUp;[Environment]::Exit(0)
