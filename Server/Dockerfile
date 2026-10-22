# Author: Maya Thabet October 22nd 2026
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y \
    build-essential \
    flex \
    bison \
    wget \
    m4 \
    python3 \
    python3-dev \
    python3-pip \
    libgmp-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /install
RUN wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz && \
    tar -xf pbc-1.0.0.tar.gz && \
    cd pbc-1.0.0 && \
    ./configure && \
    make && \
    make install && \
    ldconfig


RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm &&\
    sed -i 's/from distutils.core import/from setuptools import/g' setup.py &&\
    ./configure.sh &&\
    pip install . &&\
    mv charm charm_source_code



WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt



COPY . .



CMD ["python3", "server_socket.py"]