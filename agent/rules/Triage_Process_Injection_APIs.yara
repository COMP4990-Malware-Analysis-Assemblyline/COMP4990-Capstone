rule Triage_Process_Injection {
    meta:
        description = "Detects common APIs used for process injection and code execution"
        author = "SentinelLine Agent"
        state = "TRIAGE"

    strings:
        // Memory allocation and manipulation
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        
        // Thread creation for execution
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        
        // Context manipulation
        $api5 = "SetThreadContext" ascii wide
        $api6 = "QueueUserAPC" ascii wide

    condition:
        // Flagging if any 2 of these are present suggests a high chance of injection behavior
        2 of them
}
