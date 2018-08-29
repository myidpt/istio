FROM ubuntu:16.04
ADD citactl /
CMD exec /bin/bash -c "trap : TERM INT; sleep infinity & wait"
