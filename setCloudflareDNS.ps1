foreach ($c in Get-NetAdapter) {
  Set-DnsClientServerAddress -InterfaceIndex $c.interfaceindex -ServerAddresses ('1.1.1.3', '1.0.0.3')
}