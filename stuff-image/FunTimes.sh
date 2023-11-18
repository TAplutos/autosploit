#!/bin/bash

#!/bin/bash

#sudo apt -y install docker.io
#sudo systemctl enable docker.server
#sudo systemctl anable containerd.service
#sudo systemctl start docker
#docker --version 
#verification that docker was installed

docker container build -it FunTimes .
#building container
docker run FunTimes 
#running container with packages