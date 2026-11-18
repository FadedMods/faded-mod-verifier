rule Lua_Direct_Host_Process_Call {
    meta:
        description = "Direct host-process calls in Lua need manual review."
    strings:
        $process = /os[ \t]*\.[ \t]*(execute|popen)[ \t]*\(/
    condition:
        lua_file and $process
}
