#!/bin/sh

PORT=5000

echo "Agent: Listening on vsock port $PORT"

# Start vsock server using socat
socat -v VSOCK-LISTEN:$PORT,fork SYSTEM:/bin/agent_handler.sh
# End of script