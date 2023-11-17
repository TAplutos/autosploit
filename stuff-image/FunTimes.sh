#!/bin/bash

#!/bin/bash

#sudo apt -y install docker.io
#sudo systemctl start docker
#docker --version 
#verification that docker was installed

docker container build -t FunTimes .
#building container
docker run FunTimes 
#running container with packages