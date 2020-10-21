FROM ubuntu:latest

COPY ../Client ./start_script.sh
RUN ["chmod", "+x", "start_script.sh"]

ENTRYPOINT ["sh","./start_script.sh"]