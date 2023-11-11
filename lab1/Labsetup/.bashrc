alias dockps='docker ps --format "{{.ID}} {{.Names}}"' 
docksh() { docker exec -it $1 /bin/bash; }
