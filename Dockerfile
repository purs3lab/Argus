FROM python:3.10

WORKDIR /root

# Install dependencies
RUN apt-get -y update
RUN apt-get -y install python3-poetry  nodejs
RUN mkdir codeql_home

# Setup codeql
WORKDIR /root/codeql_home
RUN mkdir codeql-repo
RUN git clone --depth 1 https://github.com/github/codeql codeql-repo/
RUN wget https://github.com/github/codeql-cli-binaries/releases/download/v2.13.3/codeql-linux64.zip
RUN unzip codeql-linux64.zip

# Copy argus files and queries
COPY argus.py poetry.lock pyproject.toml /root/
COPY argus_components /root/argus_components
COPY qlqueries /root/qlqueries
RUN poetry install

# Now run argus
WORKDIR /root
RUN mkdir results
ENTRYPOINT ["poetry", "run", "python3", "argus.py"]
