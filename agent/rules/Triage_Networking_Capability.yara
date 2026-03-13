rule Triage_Networking_Capability {
    meta:
        description = "Detects strings and libraries associated with network communication"
        author = "SentinelLine Agent"
        state = "TRIAGE"

    strings:
        // Common network libraries
        $lib1 = "wininet.dll" ascii wide nocase
        $lib2 = "winhttp.dll" ascii wide nocase
        $lib3 = "ws2_32.dll" ascii wide nocase
        
        // High-level protocol strings
        $proto1 = "http://" ascii wide
        $proto2 = "https://" ascii wide
        $proto3 = "ftp://" ascii wide
        
        // Network-related API calls
        $api1 = "InternetOpen" ascii wide
        $api2 = "HttpSendRequest" ascii wide
        $api3 = "gethostbyname" ascii wide

    condition:
        // Flagging if a network library AND a protocol or API is found
        any of ($lib*) and (any of ($proto*) or any of ($api*))
}
