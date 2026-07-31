local socket = require('socket')

local port = arg[1] or 61616
local server = assert(socket.bind('*', port))
server:settimeout(10)

while true do
    print 'Waiting for connection...'
    local client = server:accept()
    if client then
        client:settimeout(10)

        print("Client connected")

        while true do

            local request, err = client:receive("*l")
            if err then
                print(err)
                break
            elseif request then
                print(request)
                -- client:send(request)
            end

        end

        client:close()
    end
end
