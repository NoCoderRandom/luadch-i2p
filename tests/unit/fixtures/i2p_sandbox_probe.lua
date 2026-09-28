local request_ok, request_err = http_client.request {
    url = "https://example.invalid/",
}

local socket_writable = pcall( function( )
    socket.tcp = function( ) end
end )

return {
    raw_socket_exposed = socket.tcp ~= nil,
    socket_gettime_exposed = type( socket.gettime ) == "function",
    socket_writable = socket_writable,
    raw_ssl_exposed = ssl and ssl.wrap ~= nil,
    x509_load_exposed = ssl and ssl.x509 and type( ssl.x509.load ) == "function",
    http_queued = request_ok,
    http_error = request_err,
}
