# Multipath TCP parser

Code for parsing pcap using libcap in c++

  - Takes an input .pcap dump file
  - Extracts TCP flows
  - Extracts Mutipath TCP flows


### Requirements

Dillinger uses a number of open source projects to work properly:

* C++ compiler
* libpcap
* libssl
* libcurl

### Installation

You need to do following steps:

```sh
$ git clone [reposiroty link]
```

```sh
$ make -f Makefile
$ ./Multipath [inputfile_name.pcap]
```

### Todos

 - Parsing Multipath TCP subflows data
 - Processing other TCP options like : ADD_ADDR , REMOVE_ADDR, DSS etc.





