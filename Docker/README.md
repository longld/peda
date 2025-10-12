
# Kalilinux/kali-rolling container with GDB-PEDA integrated and configured


## sethsterling/gdb-peda-kali

**Acknowledgement to: [KaliLinux](https://hub.docker.com/u/kalilinux)** - [Base_Image](https://hub.docker.com/r/kalilinux/kali-rolling) - [Repository](https://gitlab.com/kalilinux/packages/gdb-peda/-/tree/kali/master?ref_type=heads) - [Instalation Guide](https://www.kali.org/tools/gdb/) - [GDB Guide](https://docs.redhat.com/en/documentation/red_hat_developer_toolset/12/html/user_guide/chap-gdb#sect-GDB-Run)

[![Docker Pulls](https://img.shields.io/docker/pulls/sethsterling/gdb-peda-kali.svg)](https://hub.docker.com/r/sethsterling/gdb-peda-kali/) -
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/sethsterling/gdb-peda-kali)](https://hub.docker.com/r/sethsterling/gdb-peda-kali/) 
---

## 1. Pull and Run

### Pull:
```
sudo docker pull sethsterling/gdb-peda-kali
```

### Run:
```
sudo docker run -it --rm -v $PWD:/workspace sethsterling/gdb-peda-kali /workspace/{Program_Name}
```

---
## 2. Edit Dockerfile


### Dockerfile:

```
FROM kalilinux/kali-rolling:latest


# SetUp non interactive 
ENV DEBIAN_FRONTEND=noninteractive

# Update and Upgrade Packages
RUN apt update && \
    apt upgrade -y && \
    apt install -y gdb-peda

# Change INIT as https://gitlab.com/kalilinux/packages/gdb-peda/-/blob/kali/master/debian/README.Debian?ref_type=heads says
RUN echo "source /usr/share/gdb-peda/peda.py" >> ~/.gdbinit

# Start container directly with GDB
ENTRYPOINT ["/usr/bin/gdb", "-q"]

```


### Build Container:
```
sudo docker build -t gdb-peda-kali .
```

### Run Container with program volume:
```
sudo docker run -it --rm -v $PWD:/workspace sethsterling/gdb-peda-kali /workspace/{Program_Name}
```

### Notes:
1. Your program must have **execution permissions**
```
chmod +x {Program_Name}
```

2. Your directory at the time of running the container **should contain only the executable** and the files it depends on.

---
