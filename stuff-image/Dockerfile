FROM python:3.12
ADD stuff.py .
RUN apt-get update && apt-get install -y python3
#RUN apt --assume-yes install snap
RUN apt --assume-yes install pip
RUN apt --assume-yes install nmap
RUN pip install pymetasploit3
RUN python3 -m pip install --upgrade pip
RUN net-tools
#RUN apt --assume-yes install metasploit-framework
CMD ["python3", "stuff.py"]
#CMD ["bash", "more.sh"]